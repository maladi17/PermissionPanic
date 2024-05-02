import adal
import jwt


def getTokenByCred(tenantId ,appId, secret, resourceURL):
    authority_url = 'https://login.microsoftonline.com/%s' % tenantId
    context = adal.AuthenticationContext(authority_url)
    token = context.acquire_token_with_client_credentials(resourceURL,appId,secret)
    return token['accessToken']


def getPermissionByToken(token):
    decoded_payload = jwt.decode(token, options={'verify_signature': False})
    return decoded_payload["roles"]