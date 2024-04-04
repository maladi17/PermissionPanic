from attacks.handlers.user_invite_handler import UserInvite_Handler
from attacks.handlers.base_handler import Request, Response
from utils.configuration import Configuration
from attacks.handlers.application_rw_handler import ApplicationRW_Handler
from attacks.handlers.user_rw_handler import UserRW_Handler
from attacks.handlers.au_handler import AU_Handler
from attacks.handlers.team_settings_handler import TeamSettings_Handler
from attacks.handlers.team_member_handler import TeamMember_Handler
from attacks.handlers.conditional_access_handler import ConditionalAccess_Handler
from attacks.handlers.cross_tenant_handler import CrossTenant_Handler
from attacks.handlers.entitlement_handler import Entitlementntitlement_Handler
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
        team_settings_handler = TeamSettings_Handler()
        TeamMember_handler = TeamMember_Handler()
        conditional_access = ConditionalAccess_Handler()
        CrossTenant = CrossTenant_Handler()
        entitlement = Entitlementntitlement_Handler()

        application_rw_vector_attack.set_next(user_rw_vector_attack)
        user_rw_vector_attack.set_next(user_invite_handler)
        user_invite_handler.set_next(au_rw_handler)
        au_rw_handler.set_next(team_settings_handler)
        team_settings_handler.set_next(TeamMember_handler)
        TeamMember_handler.set_next(conditional_access)
        conditional_access.set_next(CrossTenant)
        CrossTenant.set_next(entitlement)

        return application_rw_vector_attack.handle(request,[])
