import requests
import colorama
from colorama import Fore, Style


def Name_Vectors(request_headers, NameSettings):
    print()
    print(
        "priv - desc")
    print()
    try:
        print("Attack vector - .")

        create_message_URL = "https://graph.microsoft.com/v1.0/users/"
        message_obj = {
            "accountEnabled": "false"
        }

        result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

        print(Fore.GREEN + "Disabled user ")
        print(Style.RESET_ALL)
        print("shay")

    except:
        pass
