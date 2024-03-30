from utils import logger
from attacks.attack_controller import AttackController
from utils import azure_utils
from utils.configuration import Configuration 
import json


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


logger = logger.createLogger('main')

def launch_attacks(tokens):
    for token in tokens:
        pass
    #ApplicationRW_Vectors(request_headers, conf["ApplicationReadWriteAll"]) - Done
    #UserRW_Vectors(request_headers, conf["UserReadWriteAll"]) - Done
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
    #MultiTenant_Vectors(request_headers,conf["multiTenant"])

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
    print(custom_fig.renderText('Shay Reuven'))

def create_tokens(tenants,resourceURL):
    tokens = []
    for tenant in tenants:
        tenantId = tenant["tenantId"]
        for application in tenant["applications"]:
            appId = list(application.keys())[0]
            secret = application[appId]
            accessToken = azure_utils.getTokenByCred(tenantId,appId,secret, resourceURL)
            roles = azure_utils.getPermissionByToken(accessToken)
            tokens.append({"tenantId": tenantId ,"appId": appId, "roles": roles, "token": accessToken })

    return tokens

def main():
    banner()
    logger.info('load configuration')
    config = Configuration('conf.json').get_config()
    logger.info('create tokens')
    apps = create_tokens(config["tenants"],'https://graph.microsoft.com')
    logger.info('searching for attack vectors')
    responses = []
    for app in apps:
        attackController = AttackController(app)
        logger.info('run attacks on tennentid: %s, appid: %s' % (app["tenantId"],app["appId"]))
        responses.append(attackController.run_attacks())

    
    
    for response in responses:
        for res in response:
            if res.status == True:
                print()
                print(json.dumps(res.to_dict()))
    # connect()


if __name__ == "__main__":
    main()
