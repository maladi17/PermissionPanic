from enum import Enum

class AttackVectors(Enum):
    ApplicationRW_Vectors = 1
    UserRW_Vectors = 2
    UserInvite_Vectors = 3
    UserEnDis_Vectors = 4
    SecDefaults_Vectors = 5
    AU_Vectors = 6
    Organization_Vectors = 7
    rolemanagemant_Vectors = 8
    TeamSettings_Vectors = 9
    TeamMember_Vectors = 10
    RoleSchedule_Vectors = 11
    mailSend_Vectors = 12
    mailbox_Vectors = 13
    GroupPIM_Vectors = 14
    exchange_Vectors = 15
    Entitlement_Vectors = 16
    lifecycle_Vectors = 17
    PolicyUserAuthMethod_Vectors = 18
    OrgAuthMeth_Vectors = 19
    Laps_Vectors = 20
    OAuthDeleg_Vectors = 21
    Conditional_access_Vectors = 22
    AppAssign_Vectors = 23
    CrossTenant_Vectors = 24
    MultiTenant_Vectors = 25
    All = 26
