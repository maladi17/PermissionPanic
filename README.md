
<img src="1.png" width="800" height="300">
<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

# Table Of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Feedback](#feedback)
- [Contributors](#contributors)
- [Acknowledgments](#acknowledgments)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction


This Tool is based on Adi Malyanker's research on application permissions in Entra ID. The tool implements more than 40 attack vectors found in the research. Pay attention that small amount of the attack vectors were found by other researchers (2-4 attacks). 

## Features

Permission you can exploit with PermissionPanic (some permissions got a couple of attack vectors):

* Application.Read.All + AppRoleAssignment.ReadWrite.All 
  
* Application.ReadWrite.All 

* AdministrativeUnit.ReadWrite.All 

* Policy.ReadWrite.ConditionalAccess

* Policy.ReadWrite.CrossTenantAccess

* Directory.ReadWrite.All

* EntitlementManagement.ReadWrite.All

* RoleManagement.ReadWrite.Exchange

* PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup

* DeviceLocalCredential.Read.All

* LifecycleWorkflows.ReadWrite.All

* Mail.Send + Mail.ReadBasic

* MailboxSettings.ReadWrite

* MultiTenantOrganization.ReadWrite.All

* DelegatedPermissionGrant.ReadWrite.All

* Organization.ReadWrite.All

* UserAuthenticationMethod.ReadWrite.All

* RoleAssignmentSchedule.ReadWrite.Directory

* Policy.ReadWrite.SecurityDefaults

* TeamMember.ReadWrite.All

* TeamSettings.ReadWrite.All

* User.EnableDisableAccount.All

* User.Invite.All

* User.ReadWrite.All

## output example
[output example]https://github.com/maladi17/PermissionPanic/blob/main/output.csv)

## Feedback

Feel free to send us feedback on <some contact way> or open an issue. Feature requests are always welcome. If you wish to contribute, please contact us.

## Contributors

* Adi Malyanker - A security researcher in Semperis. Made the research and developed the tool's indicators.
* Shay Reuven - A security architect in Bank Leumi. Developed the tool's infrastructure.

## Acknowledgments

Thanks to [Semperis](https://www.semperis.com/) for supporting this research.
