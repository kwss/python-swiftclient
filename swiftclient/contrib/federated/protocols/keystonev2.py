import urllib
import urllib2
import json
import getpass
import BaseHTTPServer
import os
import webbrowser
from swiftclient.contrib.federated import federated_exceptions, federated_utils
import ssl

## Sends the authentication request to the IdP along
# @param idpEndpoint The IdP address
# @param idpRequest The authentication request returned by Keystone
def getIdPResponse(idpEndpoint, idpRequest, realm=None):
    print "\nInitiating Authentication against: "+realm["name"]+"\n"
    # Get the unscoped token
    # 1. Get the user name
    chosen = False
    user = None
    while not chosen:
        try:
            user = raw_input("Please enter your username: ")
            chosen = True
        except:
            print "Invalid input, please try again"
    # 2. Get the password
    chosen = False
    password = None
    while not chosen:
        try:
            password = getpass.getpass()
            chosen = True
        except:
            print "Invalid input, please try again"

    # Insert creds
    req = json.loads(idpRequest)
    req['auth']['passwordCredentials']['username'] = user
    req['auth']['passwordCredentials']['password'] = password
    # Contact Keystone V2
    unscoped = json.loads(request(idpEndpoint+'/tokens', method='POST', data=req).read())
    print "Successfully Logged In\n"
    # Get the list of tenants
    tenants = json.loads(request(idpEndpoint+'/tenants', method='GET', header={'X-Auth-Token':unscoped['access']['token']['id']}).read())
    # Offer the user the choice of tenants
    tenant = federated_utils.selectTenantOrDomain(tenants['tenants'],serverName=realm["name"])
    # Get the scoped token
    newReq = {"auth":{"tenantName": tenant["name"], "token":{"id":unscoped["access"]["token"]["id"]}}}
    scoped = json.loads(request(idpEndpoint+'/tokens', method='POST', data=newReq).read())
    print "\nSuccessfully Authorised to access: "+tenant["description"]+"\n"
    # Return scoped token
    return scoped

## Send a request that will be process by the V2 Keystone
def request(keystoneEndpoint, data={}, method="GET", header={}):
    headers = header
    if method == "GET":
        data = urllib.urlencode(data)
        req = urllib2.Request(keystoneEndpoint + data, headers = header)
        response = urllib2.urlopen(req)
    elif method == "POST":
        data = json.dumps(data)
        headers['Content-Type'] = 'application/json'
        req = urllib2.Request(keystoneEndpoint, data, header)
        response = urllib2.urlopen(req)
    return response
