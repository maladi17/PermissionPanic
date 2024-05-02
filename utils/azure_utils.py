import adal
import jwt
from utils import logger

logger = logger.createLogger('utils.azure_utils')

def getTokenByCred(tenantId ,appId, secret, resourceURL):
    authority_url = 'https://login.microsoftonline.com/%s' % tenantId
    context = adal.AuthenticationContext(authority_url)
    token = context.acquire_token_with_client_credentials(resourceURL,appId,secret)
    # logger.debug('getTokenByCred() - tenantId: %s ,appId: %s, secret: %s, resourceURL: %s - login successfully' % (tenantId ,appId, secret, resourceURL))
    # logger.debug('jwt: %s' % str(decoded_payload))
    return token['accessToken']


def getPermissionByToken(token):
    decoded_payload = jwt.decode(token, options={'verify_signature': False})
    return decoded_payload["roles"]