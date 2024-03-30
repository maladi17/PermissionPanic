from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Optional,List
import json


class Request():
    def __init__(self, token, attack_config,tenantId,appId,roles) -> None:
        self.token = token
        self.request_headers = {'Authorization': 'bearer %s' % (self.token)}
        self.attack_config = attack_config
        self.tenantId = tenantId
        self.appId= appId
        self.roles =roles

class Response():
    def __init__(self, attack_name, tenantId,appId,status,message) -> None:
        self.attack_name = attack_name
        self.tenantId = tenantId
        self.appId= appId
        self.status = status
        self.message = message
    
    def to_dict(self):
        return {
            "attack_name": self.attack_name,
            "tenantId": self.tenantId,
            "appId": self.appId,
            "status": self.status,
            "message": self.message
        }
    def __str__(self) -> str:
        return json.dumps(self.to_dict())

class Handler(ABC):
    """
    The Handler interface declares a method for building the chain of handlers.
    It also declares a method for executing a request.
    """

    @abstractmethod
    def set_next(self, handler: Handler) -> Handler:
        pass

    @abstractmethod
    def handle(self, request) -> Optional[str]:
        pass


class AttackHandler(Handler):
    """
    The default chaining behavior can be implemented inside a base handler
    class.
    """

    _next_handler: Handler = None

    def set_next(self, handler: Handler) -> Handler:
        self._next_handler = handler
        return handler

    @abstractmethod
    def handle(self, request:Request, responses: List[Response]) ->Optional[List[Response]]:
        if self._next_handler:
            return self._next_handler.handle(request,responses)

        return responses

