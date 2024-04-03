from attacks.handlers.user_invite_handler import UserInvite_Handler
from attacks.handlers.base_handler import Request, Response
from utils.configuration import Configuration
from attacks.handlers.application_rw_handler import ApplicationRW_Handler
from attacks.handlers.user_rw_handler import UserRW_Handler
from attacks.handlers.au_handler import AU_Handler
from attacks.handlers import *

from utils import logger
from typing import Optional, List

logger = logger.createLogger('attacks.attack_controller')


class AttackController:
    def __init__(self,app):
        self.tenantId =app["tenantId"]
        self.appId = app["appId"]
        self.token = app["token"]
        self.roles = app["roles"]
        

    def run_attacks(self) ->Optional[List[Response]]:
        
        conf = Configuration().get_config()
        request = Request(self.token,conf,self.tenantId,self.appId,self.roles)
        
        application_rw_vector_attack = ApplicationRW_Handler()
        user_rw_vector_attack = UserRW_Handler()
        user_invite_handler = UserInvite_Handler()
        au_rw_handler = AU_Handler()

        application_rw_vector_attack.set_next(user_rw_vector_attack)
        user_rw_vector_attack.set_next(user_invite_handler)
        user_invite_handler.set_next(au_rw_handler)
        
        return application_rw_vector_attack.handle(request,[])
