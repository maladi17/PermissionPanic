from confFile import readConf
from AppRW import ApplicationRW_Vectors
from userInvite import UserInvite_Vectors
from userEnDis import UserEnDis_Vectors
from administrativeUnitRW import AU_Vectors
from userRW import UserRW_Vectors
from security_defaults import SecDefaults_Vectors
from organization import Organization_Vectors
from rolemanagement import rolemanagemant_Vectors
from teammember import TeamMember_Vectors
from teamsettings import TeamSettings_Vectors
from roleschedule import RoleSchedule_Vectors
from mailsend import mailSend_Vectors
from mailsettings import mailbox_Vectors
from exchange import exchange_Vectors
from pimGroups import GroupPIM_Vectors
from entitlement import Entitlement_Vectors
from lifecycle import lifecycle_Vectors
from change_mfa import PolicyUserAuthMethod_Vectors
from organization_and_authnticationmethod import OrgAuthMeth_Vectors
from appassignment import AppAssign_Vectors
from laps import Laps_Vectors
from outhDeleg import OuthDeleg_Vectors
from conditional_access import Conditional_access_Vectors
from CrossTenantAccess import CrossTenant_Vectors
from multiTenant import MultiTenant_Vectors
from pyfiglet import Figlet
import adal
import jwt

tenantID = "6af675bf-f240-4c03-86c4-56f4b73342da"
applications = {

    "b63e4c36-2b0b-4598-ab57-ea0bd97eef38": "4ZB8Q~H8_ooUzT6Y8v1.BMY3nUTzJgSjIlc6OaQ-",  # ApplicationReadWriteAll
    "ea82d3a1-65eb-482e-8e01-c9ad49c2ea8a": "I6N8Q~XnL62~ZzT0VBOyXqlzdibzglRHjnsjCaPX",  # User.RW.all
    "6bb36e66-9b82-4a6d-95a4-9b87d0511e23": "B4J8Q~FkAiWj7n2Nkai_4pOP~wQcHzieItuTNcvp",  # user.invite
    "f398fb28-4646-4ac9-a375-02a06974de7b": "tbr8Q~m4bvg.CGtkgdDjn0tPgvmF2OFHuSYhYb4y",  # userEnDis
    "2ced8283-4523-40df-a8d4-805f76f02434": "kOd8Q~52KxqsJiixiO8hJD-IWLSK1jOa555tTbPp",  # security_defaults
    "b82ad3e1-3e2a-44db-9876-d5b2d110b528": "EH88Q~Se1ErZDdW5Z-GxtDmC7YYjxdbyUxL05dxe",  # administrativeUnitRW
    "dd769865-3a7b-4f4a-8bc7-95fa8ef03e57":  "Oon8Q~E_oLegHVWx5Juh-CGnKi7U9wYHrm1itde8",  # OrganizationalBranding.ReadWrite.All
    "f7bdd53f-0811-4997-a9c1-26c1d298a5ec":  "KjI8Q~DNBiNTJuV1Fvo6ht3Pr_t9GSmCZfV-odoJ",   # organization.RW.all
    "122f8314-99d3-4687-9963-a5efd584a5dd":  "hu_8Q~5~oyJXo.UHkOG5WVww2G10b2VvW5Oy.b-E",     # rolemanagement
    "1a532be0-c7bf-4cb2-ac08-1df4cf1c303d": "7dy8Q~w3aZC0XZaq8YHHGw3o4GkV-dHy_oc7RdBP",  # teamsettings
    "4d284544-b740-44ea-be11-d904470bef14": "XBO8Q~GHyonLxTj8hlHZ3GseRsUIlZHFarz0Eb1U",  #  teamBasicRead
    "9e8d0068-4d22-4226-893d-4b4383ab40ae": "HZh8Q~VCPGvsaGt6iBCKB3VcniE8DNEenA70VbG.",#   teammember  (need to add attack vector for TeamMember.ReadWriteNonOwnerRole.All)
    "bb1c7b86-3c4e-45b4-9fb5-207b1685c352": "AAK8Q~P-MPe0-N3y~jMaGIg4EYbMfoO3XtLjGa6-",  # roleAssignmentSchedule
    "d00d37ae-9910-4945-af65-bdd492e11a43": "Osc8Q~xhc3ICnMqFQp0YOT04rhuM4ildH7daKbNc",  # mail.send
    "f42f3158-48c0-48d2-80fd-9190c741be8a": "Gek8Q~bSKjpWrKCZzjtJmOoESvzBjikUhJkEBajO",  # mailsettings
    "7b3d600c-ae69-45d8-9db8-140eafc82ea7": "CFH8Q~fu~JHUzdLh.y6v.eJXDeH8QJdWaIQRubXS",  # PrivilegedAssignmentSchedule
    "e72fcdde-c7b7-4aac-8545-68180609c3ca": "ZSR8Q~vedEMUIeeEfGutzW.KlPGwHvT3tgYAzdhY", #    exchange
    "46016fec-fd45-477f-a7af-eaa9546ff8cb": "HnX8Q~3LFxHex~X0WmCOUJUI~SMEuDVNPqo4YbPD", #    Entitlement_RW
    "42bf09a0-5ad6-4241-8302-aac04a279ed8": "88p8Q~MaoYtMRvjAtfj7hSxvBtLlHxIX3~LkMdxL",  #   Policy.ReadWrite.AuthenticationMethod+UserAuthenticationMethod.ReadWrite.All
    "20b1178c-ea1c-4c33-aa63-5e16f73d086c": "lwY8Q~PrhHukA4X4SB1_aVSSLnZAwZFFstfslaJA",  #   organization.readwrite.all + policy.readwrite.authnticationmethod
    "46c95666-25d7-405a-8a4c-e366489beeb6": "NwU8Q~vdpP.i59_SButDanQKA9xg0CfSJnjGBcxs",  #   laps
    "f54384d7-68d2-40f5-a96c-9dd9b9c64392": "yxF8Q~Gp-kzliWn_EE2LY9BZrMu6c~WSfsgN.aiG",  #   directory.readwrite.all
    "3a6e1619-a4b5-46d3-b921-90ea6425d1ae": "ylb8Q~oj-bvYwmEpzO8GwpJeoDPBKWiMau3kscIj",  #   oauthdeleg
    "853b7405-a686-4b20-819a-a1531f60be5f": "lYQ8Q~vGDcOz~dCWIAmdeJMNjioMkdmgOZ6G-deX",  #   conditional_access
    "b652cb35-04ac-4b91-bff8-7d0f8a4850cb": "4ql8Q~cIehqasmsQUPGEPbJSg2r0E.e5s4sRta1A",  #   appassignment
    "3ba22762-810f-49bc-86ab-a2d75db5e950": "8pk8Q~cwIEmIqHa~EnXLRrRSbFJyYqug0XUNaaU0",  #   appassign_directory
    "fb70de81-ef27-40b6-883b-c9d41503d3a7": "BtX8Q~P3DpbG_t_d5vpUM6WkA0h1s9hjRnkCic5X",  #   Policy.ReadWrite.CrossTenantAccess
    "977cc5bb-2ca1-41c9-ae0c-dbae191907f4": "qxH8Q~kWDXYrflTS4g8CytyF0pCcxIeZgj_ApcyG"  #   multitenant
}
filename = "conf.json"

Othertenant = "1d4d77f4-1713-4c31-b958-59500ea8d92e"
OtherApps = {
    "823cb9f9-1589-4357-acb8-48134efa6a86":"JaT8Q~_AjGpnGqPKwi4N6zpQyQiiqOqu-QVmicdB"
}

def launch_attacks(request_headers, conf):
    pass
    #ApplicationRW_Vectors(request_headers, conf["ApplicationReadWriteAll"])
    #UserRW_Vectors(request_headers, conf["UserReadWriteAll"])
    #UserInvite_Vectors(request_headers, conf["UserInvite"], tenantID)
    #UserEnDis_Vectors(request_headers, conf["UserEnDis"])
    #SecDefaults_Vectors(request_headers)
    #AU_Vectors(request_headers, conf["administrativeUnits"])
    #Organization_Vectors(request_headers, conf["organization"])
    #rolemanagemant_Vectors(request_headers, conf["roleManagement"])
    #TeamSettings_Vectors(request_headers, conf["TeamSettings"])
    #TeamMember_Vectors(request_headers, conf["TeamsMemSettings"])
    #RoleSchedule_Vectors(request_headers,conf["RoleSchedule"])
    #mailSend_Vectors(request_headers,conf["mailSend"])
    #mailbox_Vectors(request_headers,conf["mailbox"])
    #GroupPIM_Vectors(request_headers,conf["Gpim"])
    #exchange_Vectors(request_headers,conf["exchange"])
    #Entitlement_Vectors(request_headers, conf["Entitlement"])
    #lifecycle_Vectors(request_headers,conf["lifecycle"])
    #PolicyUserAuthMethod_Vectors(request_headers, conf["UserPolicyAuth"])
    #OrgAuthMeth_Vectors(request_headers,conf["OrgAuthMeth"], tenantID)
    #Laps_Vectors(request_headers)
    #OuthDeleg_Vectors(request_headers, conf["oauthDeleg"])
    #Conditional_access_Vectors(request_headers,conf["conditional_access"])
    #AppAssign_Vectors(request_headers,conf["appAssignment"])
    #CrossTenant_Vectors(request_headers,conf["crossTenant"])
    MultiTenant_Vectors(request_headers,conf["multiTenant"])

def connect():
    conf = readConf(filename)
    tenants = conf["tenants"]
    for tenant in tenants:
        for tenantId in tenant.keys():
            appsSet = tenant[tenantId]
            for application in appsSet:
            

                print("-------------------------------" + application + "-------------------------------")
                resource_URL = 'https://graph.microsoft.com'
                authority_url = 'https://login.microsoftonline.com/%s' % tenantId

                context = adal.AuthenticationContext(authority_url)

                token = context.acquire_token_with_client_credentials(
                    resource_URL,
                    application,
                    appsSet[application])
                decoded_payload = jwt.decode(token['accessToken'], options={'verify_signature': False})
                print("Achieved token: " + str(decoded_payload))

                request_headers = {'Authorization': 'bearer %s' % (token['accessToken'])}
                launch_attacks(request_headers,conf)

    for key in OtherApps:
        print("-------------------------------" + key + "-------------------------------")
        resource_URL = 'https://graph.microsoft.com'
        authority_url = 'https://login.microsoftonline.com/%s' % Othertenant

        context = adal.AuthenticationContext(authority_url)

        token = context.acquire_token_with_client_credentials(
            resource_URL,
            key,
            OtherApps[key])
        decoded_payload = jwt.decode(token['accessToken'], options={'verify_signature': False})
        print("Achieved token: " + str(decoded_payload))

        request_headers = {'Authorization': 'bearer %s' % (token['accessToken'])}
        launch_attacks(request_headers)


def banner():
    custom_fig = Figlet(font='Fender')
    print(custom_fig.renderText('PermissionPanic'))
    custom_fig = Figlet(font='Digital')
    print(custom_fig.renderText('Adi Malyanker'))


def main():
    banner()
    connect()


if __name__ == "__main__":
    main()
