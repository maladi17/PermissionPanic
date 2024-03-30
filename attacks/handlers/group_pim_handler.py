from typing import List
from attacks.handlers.base_handler import AttackHandler, Request, Response
from utils import logger
import requests

logger = logger.createLogger('attacks.handlers.group_pim_handler')


class GroupPIM_Handler(AttackHandler):
    def handle(self, request: Request,responses:List[Response]):
        # TODO map request.roles to fit with this attack
        if True:
            pass          
            
        return super().handle(request,responses)