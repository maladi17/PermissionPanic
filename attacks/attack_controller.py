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
from attacks.handlers.exchange_handler import Exchange_Handler
from attacks.handlers.user_en_dis_handler import UserEnDis_Handler
from attacks.handlers.mail_send_handler import MailSend_Handler
from attacks.handlers.group_pim_handler import GroupPIM_Handler
from attacks.handlers.laps_handler import Laps_Handler
from attacks.handlers.sec_defaults_handler import SecDefaults_Handler
from attacks.handlers.app_assign_handler import AppAssign_Handler
from attacks.handlers.rolemanagemantCustom_handler import RolemanagemantCustom_Handler
from attacks.handlers.rolemanagemantPersistance_handler import RolemanagemantPersistance_Handler
from attacks.handlers.rolemanagemant_handler import Rolemanagemant_Handler
from attacks.handlers.oauth_deleg_handler  import OAuthDeleg_Handler
from attacks.handlers.org_auth_meth_handler import OrgAuthMeth_Handler
from attacks.handlers.directory_handler import Directory_Handler
from attacks.handlers.role_schedule_handler import RoleSchedule_Handler
from attacks.handlers.organization_handler import Organization_Handler
from attacks.handlers.multitenant_handler import Multitenant_Handler
from attacks.handlers.mailbox_handler import MailboxPhish_Handler
from attacks.handlers.policy_user_auth_method_handler import PolicyUserAuthMethod_Handler
from attacks.handlers.mailboxRedirect_handler import MailboxRedirect_Handler
from attacks.handlers.policy_user_takeover_handler import PolicyUserAuthTakeover_Handler
from attacks.handlers.lifecycle_handler import Lifecycle_Handler
from attacks.handlers.lifecycle_group_handler import Lifecycle_GroupHandler
from attacks.handlers.lifecycle_disable_handler import Lifecycle_DisableHandler
from attacks.handlers import *
import pandas as pd

from utils import logger
from typing import Optional, List

logger = logger.createLogger('attacks.attack_controller')


class AttackController:
    def __init__(self,app):
        self.tenantId =app["tenantId"]
        self.appId = app["appId"]
        self.token = app["token"]
        self.roles = app["roles"]
        self.responses = []
        

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
        exchange = Exchange_Handler()
        UserEnDis = UserEnDis_Handler()
        mailSend = MailSend_Handler()
        gpim = GroupPIM_Handler()
        laps = Laps_Handler()
        secDef = SecDefaults_Handler()
        appAssing = AppAssign_Handler()
        roleCustom = RolemanagemantCustom_Handler()
        rolePersist = RolemanagemantPersistance_Handler()
        roleManagement = Rolemanagemant_Handler()
        oauth = OAuthDeleg_Handler()
        directory = Directory_Handler()
        roleSchedule = RoleSchedule_Handler()
        org_meth = OrgAuthMeth_Handler()
        org_brand = Organization_Handler()
        Multitenant = Multitenant_Handler()
        mailboxPhish = MailboxPhish_Handler()
        mailboxRedirect = MailboxRedirect_Handler()
        policy_user_mfa = PolicyUserAuthMethod_Handler()
        policy_user_takeover = PolicyUserAuthTakeover_Handler()
        lifecycle = Lifecycle_Handler()
        lifecycleGroup = Lifecycle_GroupHandler()
        lifecycleDisable = Lifecycle_DisableHandler()

        application_rw_vector_attack.set_next(user_rw_vector_attack)
        user_rw_vector_attack.set_next(user_invite_handler)
        user_invite_handler.set_next(au_rw_handler)
        au_rw_handler.set_next(team_settings_handler)
        team_settings_handler.set_next(TeamMember_handler)
        TeamMember_handler.set_next(conditional_access)
        conditional_access.set_next(CrossTenant)
        CrossTenant.set_next(entitlement)
        entitlement.set_next(exchange)
        exchange.set_next(UserEnDis)
        UserEnDis.set_next(mailSend)
        mailSend.set_next(gpim)
        gpim.set_next(laps)
        laps.set_next(secDef)
        secDef.set_next(appAssing)
        appAssing.set_next(roleCustom)
        roleCustom.set_next(rolePersist)
        rolePersist.set_next(roleManagement)
        roleManagement.set_next(oauth)
        oauth.set_next(directory)
        directory.set_next(roleSchedule)
        roleSchedule.set_next(org_meth)
        org_meth.set_next(org_brand)
        org_brand.set_next(Multitenant)
        Multitenant.set_next(mailboxPhish)
        mailboxPhish.set_next(mailboxRedirect)
        mailboxRedirect.set_next(policy_user_mfa)
        policy_user_mfa.set_next(policy_user_takeover)
        policy_user_takeover.set_next(lifecycle)
        lifecycle.set_next(lifecycleGroup)
        lifecycleGroup.set_next(lifecycleDisable)
        self.responses = application_rw_vector_attack.handle(request,[])


    def get_responses_df(self):
        data = [(response.attack_name, response.tenantId, response.appId, response.status, response.message) for response in self.responses]
        return pd.DataFrame(data, columns=['Attack Name', 'Tenant ID', 'App ID', 'Status', 'Message'])
        
        
        
        
