'''
 * Copyright (c) 2013, University of Kent
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 1. Neither the name of the University of Kent nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * 2. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.
 *
 * 3. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 4. YOU AGREE THAT THE EXCLUSIONS IN PARAGRAPHS 2 AND 3 ABOVE ARE REASONABLE
 * IN THE CIRCUMSTANCES.  IN PARTICULAR, YOU ACKNOWLEDGE (1) THAT THIS
 * SOFTWARE HAS BEEN MADE AVAILABLE TO YOU FREE OF CHARGE, (2) THAT THIS
 * SOFTWARE IS NOT "PRODUCT" QUALITY, BUT HAS BEEN PRODUCED BY A RESEARCH
 * GROUP WHO DESIRE TO MAKE THIS SOFTWARE FREELY AVAILABLE TO PEOPLE WHO WISH
 * TO USE IT, AND (3) THAT BECAUSE THIS SOFTWARE IS NOT OF "PRODUCT" QUALITY
 * IT IS INEVITABLE THAT THERE WILL BE BUGS AND ERRORS, AND POSSIBLY MORE
 * SERIOUS FAULTS, IN THIS SOFTWARE.
 *
 * 5. This license is governed, except to the extent that local laws
 * necessarily apply, by the laws of England and Wales.
'''


'''
Created on 8 March 2013

@author: Vincent Giersch
'''

import copy
import json
import urllib3
import logging
import moonshot
from swiftclient.contrib.federated import federated_exceptions, federated_utils

LOG = logging.getLogger('swiftclient')
LOG.addHandler(logging.StreamHandler())
LOG.setLevel(logging.DEBUG)

class MoonshotException(Exception):
    pass

class MoonshotNegociation(object):
    def __init__(self, keystoneEndpoint, serviceName, mechanism, idpRequest, requestPool, realm):
        self.realm = realm
        self.context = None
        self.serviceName = serviceName
        self.mechanism = mechanism
        
        self.requestPool = requestPool
        self.keystoneEndpoint = keystoneEndpoint
        self.idpRequest = idpRequest
        self.idpResponse = {'negotiation': ''}

    def negociation(self):
        result, self.context = moonshot.authGSSClientInit(self.serviceName,
                                                          moonshot.GSS_C_MUTUAL_FLAG | moonshot.GSS_C_SEQUENCE_FLAG,
                                                          self.mechanism)
        if result != 1:
            raise MoonshotException('moonshot.authGSSServerInit returned result %d' % result)
        negociation = moonshot.AUTH_GSS_CONTINUE
        while negociation != moonshot.AUTH_GSS_COMPLETE:
            negociation = self.negociationStep()
        LOG.info("\nAuthentication successful using \"%s\" moonshot identity.\n", moonshot.authGSSClientUserName(self.context))

    def negociationStep(self):
        result = moonshot.authGSSClientStep(self.context, self.idpResponse['negotiation'])

        # Build request using GSS challenge
        idpRequest = copy.copy(self.idpRequest)
        idpRequest['negotiation'] = moonshot.authGSSClientResponse(self.context);

        # Send request only if the challenge is not empty (end of negotiation)
        if idpRequest['negotiation'] is not None:
            self.idpResponse = self.negociationRequest(idpRequest)
            LOG.debug("response: %r", json.dumps(self.idpResponse))
        LOG.debug("authGSSClientStep: %d", result)
        return result

    def negociationRequest(self, body):
        headers = {'X-Authentication-Type': 'federated'}
        body = json.dumps({'realm': self.realm, 'idpResponse': body})
        LOG.debug("request: %s", body)
        return json.loads(self.requestPool.urlopen('POST', self.keystoneEndpoint, body = body, headers = headers).data)

## Sends the authentication request to the IdP along
# @param idpEndpoint {u'serviceName': u'keystone@moonshot', u'mechanism': u'{1 3 6 1 5 5 15 1 1 18}'}
# @param idpRequest The authentication request returned by Keystone
def getIdPResponse(keystoneEndpoint, idpEndpoint, idpRequest, requestPool, realm=None):
    m = MoonshotNegociation(keystoneEndpoint, idpEndpoint['serviceName'], idpEndpoint['mechanism'], idpRequest, requestPool, realm)
    m.negociation()
    return None
