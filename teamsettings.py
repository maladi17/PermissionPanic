import requests
import colorama
from colorama import Fore, Style


def TeamSettings_Vectors(request_headers, TeamsSettings):
    print()
    print(
        "TeamSettings.ReadWrite.All - Read and change all teams' settings, without a signed user.")
    print(
        "TeamSettings.ReadBasic.All - Get a list of all teams, without a signed-in user.")
    print()
    try:
        print("Attack vector - initial access")
        if len(TeamsSettings['teamNames']) == 0:
            create_message_URL = "https://graph.microsoft.com/beta/teams/"
            result = requests.get(create_message_URL, headers=request_headers)
            if result.status_code == 200:
                print(Fore.BLUE + "Enter the following links to join:")
                print(Style.RESET_ALL)
                res = result.json()
                for channel in res["value"]:
                    print(Fore.GREEN + channel["id"] + " : " + channel['displayName'] + Style.RESET_ALL)
                    create_message_URL = "https://graph.microsoft.com/beta/teams/" + channel["id"]
                    teamdata = requests.get(create_message_URL, headers=request_headers)
                    teamsres = teamdata.json()

                    print(Fore.GREEN + teamsres['webUrl'] + Style.RESET_ALL)


        else:
            for team in TeamsSettings["teamNames"]:
                create_message_URL = "https://graph.microsoft.com/beta/teams/" + team
                teamdata = requests.get(create_message_URL, headers=request_headers)
                teamsres = teamdata.json()
                print(Fore.BLUE + "Enter the following links to join:" + Style.RESET_ALL)

                print(Fore.GREEN + teamsres['webUrl'] + Style.RESET_ALL)


    except:
        pass
