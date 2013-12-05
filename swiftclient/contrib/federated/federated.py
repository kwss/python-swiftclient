import imp
import os
import json
import BaseHTTPServer
import ssl
import urlparse
import urllib2
import urllib3
import webbrowser
import federated_exceptions as fe
import federated_utils as futils

## The super-function calls different API methods to obtain the scoped token
# @param keystoneEndpoint The keystone url
# @param realm The IdP the user will be using
# @param tenantFn The tenant friendly name the user wants to use
def federatedAuthentication(keystoneEndpoint, realm = None, tenantFn = None, v3 = False):
    keystoneEndpoint+="/auth/tokens"
    realms = getRealmList(keystoneEndpoint)
    if realm is None or {'name': realm} not in realms['providers']:
        realm = futils.selectRealm(realms['error']['identity']['federated']['providers'])
    request = getIdPRequest(keystoneEndpoint, realm)
    # Load the correct protocol module according to the IdP type
    protocol = realm['type'].split('.')[1]
    processing_module = load_protocol_module(protocol)
    requestPool = urllib3.PoolManager()
    response = processing_module.getIdPResponse(keystoneEndpoint, request['error']['identity']['federated'], request['error']['identity']['federated'], requestPool, realm)

    tenantData, token_id = getUnscopedToken(keystoneEndpoint, response, requestPool, realm)
    #tenant = futils.getTenantId(tenantData['token']['extras']['projects'], tenantFn)
    tenant = None
    if tenant is None:
        tenant = futils.selectTenantOrDomain(tenantData['token']['extras']['projects'])
        if tenant.get("project", None) is None and tenant.get("domain", None) is None:
            tenant = tenant["id"]
            type = "project"
        else:
            if tenant.get("domain", None) is None:
                tenant = tenant["project"]["id"]
                type = "project"
            else:
                tenant = tenant["domain"]["id"]
                type = "domain"
    scopedToken, token_id = swapTokens(keystoneEndpoint, token_id, type, tenant)
    scopedToken["token"]['id'] = token_id
    return scopedToken

def load_protocol_module(protocol):
    ''' Dynamically load correct module for processing authentication
        according to identity provider's protocol'''
    return imp.load_source(protocol, os.path.dirname(__file__)+'/protocols/'+protocol+".py")

## Get the list of all the IdP available
# @param keystoneEndpoint The keystone url
def getRealmList(keystoneEndpoint):
    data = {"auth": {
        "identity":{"methods":["federated"], "federated":{"phase":"discovery"}}}}
    resp = futils.middlewareRequest(keystoneEndpoint, data, 'POST')
    info = json.loads(resp.data)
    return info

## Get the authentication request to send to the IdP
# @param keystoneEndpoint The keystone url
# @param realm The name of the IdP
def getIdPRequest(keystoneEndpoint, realm):
    data =  {"auth": {
        "identity":{"methods":["federated"], "federated":{"phase":"request", "provider_id":realm['id']}}}}
    resp = futils.middlewareRequest(keystoneEndpoint, data, 'POST')
    info = json.loads(resp.data)
    return info

# This variable is necessary to get the IdP response
response = None

## Sends the authentication request to the IdP along 
# @param idpEndpoint The IdP address
# @param idpRequest The authentication request returned by Keystone
def getIdPResponse(idpEndpoint, idpRequest):
    global response
    response = None
    config = open(os.path.join(os.path.dirname(__file__),"config/federated.cfg"), "Ur")
    line = config.readline().rstrip()
    key = ""
    cert = ""
    timeout = 300
    while line:
        if line.split('=')[0] == "KEY":
            key = line.split("=")[1].rstrip()

        if line.split("=")[0] == "CERT":
            cert = line.split("=")[1].rstrip()
	if line.split('=')[0] == "TIMEOUT":
	    timeout = int(line.split("=")[1])
        line = config.readline().rstrip()
    config.close()
    if key == "default":
	key = os.path.join(os.path.dirname(__file__),"certs/server.key")
    if cert == "default":
        cert = os.path.join(os.path.dirname(__file__),"certs/server.crt")
    webbrowser.open(idpEndpoint + idpRequest)
    class RequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
        
        def log_request(code=0, size=0):
            return
        def log_error(format="", msg=""):
            return
        def log_request(format="", msg=""):
            return

        def do_POST(self):
            global response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            varLen = int(self.headers["Content-Length"])
            #response = urlparse.parse_qs(self.rfile.read(varLen))
            response = self.rfile.read(varLen)
            if response is None:
                self.wfile.write("An error occured.")
                raise federated_exceptions.CommunicationsError()
            self.wfile.write("You have successfully logged in. "
                             "You can close this window now.")
    httpd = BaseHTTPServer.HTTPServer(('localhost', 8080), RequestHandler)
    try:
    	httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=key, certfile=cert, server_side=True)
	httpd.socket.settimeout(1)
    except BaseException as e:
	print e.value
    count = 0
    while response is None and count < timeout:
    	try:
            httpd.handle_request()
	    count = count + 1
        except Exception as e:
	    print e.value
    if response is None:
	print ("There was no response from the Identity Provider or the request timed out")
        exit("An error occurred, please try again")
    return response

## Get an unscoped token for the user along with the tenants list
# @param keystoneEndpoint The keystone url
# @param idpResponse The assertion retreived from the IdP
def getUnscopedToken(keystoneEndpoint, idpResponse, requestPool, realm = None):
    if realm is None:
	data = {"auth": {"identity":{"methods":["federated"], "federated":{"phase":"validate", "data":idpResponse}}}}
    else:
    	data = {"auth": {"identity":{"methods":["federated"], "federated":{"phase":"validate", "provider_id":realm['id'], "data":idpResponse}}}}
    resp = futils.middlewareRequest(keystoneEndpoint, data, 'POST', requestPool)
    info = json.loads(resp.data)
    return info, resp.getheader("x-subject-token")

## Get a tenant-scoped token for the user
# @param keystoneEndpoint The keystone url
# @param idpResponse The assertion retreived from the IdP
# @param tenantFn The tenant friendly name
def getScopedToken(keystoneEndpoint, idpResponse, tenantFn):
    response = getUnscopedToken(keystoneEndpoint, idpResponse)
    type, tenantId = futils.getTenantId(response["tenants"])
    if tenantId is None:
        print "Error the tenant could not be found, should raise InvalidTenant"
    scoped = swapTokens(keystoneEndpoint, response["unscopedToken"], type, tenantId)
    return scoped

## Get a scoped token from an unscoped one
# @param keystoneEndpoint The keystone url
# @param unscopedToken The unscoped authentication token obtained from getUnscopedToken()
# @param tenanId The tenant Id the user wants to use
def swapTokens(keystoneEndpoint, unscopedToken, type, tenantId):
    data = {'auth' : {'token' : {'id' : unscopedToken}, type : tenantId}}
    if "v3" in keystoneEndpoint:
       data = {"auth": {"identity": {"methods": ["token"],"token": {"id": unscopedToken}}, "scope":{}}}
       if type == 'domain':
           data["auth"]["scope"]["domain"] = {"id": tenantId}
       else:
           data["auth"]["scope"]["project"] = {"id": tenantId}
    header = {"X-AUTH-TOKEN":unscopedToken}
    resp = futils.middlewareRequest(keystoneEndpoint, data,'POST', withheader = False, altheader=header)
    return json.loads(resp.data), resp.getheader("x-subject-token")
