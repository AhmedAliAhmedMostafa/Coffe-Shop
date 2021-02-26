import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'coffesta.eu.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'http://127.0.0.1:5000/'
public_key_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    if 'Authorization' not in request.headers:
        raise AuthError("The request doesn't contain Authorization header.", 401)
    header = request.headers['Authorization']
    header_values = header.split(' ')
    if len(header_values) != 2:
        raise AuthError("Malformed authorization header.", 401)
    if header_values[0].lower() != "bearer":
        raise AuthError("Malformed authorization header.", 401)
    return header_values[1]

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    if "permissions" not in payload:
        raise AuthError("Payload must contain permissions array.", 403)
    if permission not in payload['permissions']:
        raise AuthError("The user isn't authorized to use this api", 403)
    return True
'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    token_header = jwt.get_unverified_header(token)
    public_keys = json.loads(urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json').read())
    if 'kid' not in token_header:
        raise AuthError({
            "Malformed token."
        }, 401)
    key_found = False

    for key in public_keys['keys']:
        if key['kid'] == token_header['kid']:
            rsa_public_key_data = key
            key_found = True
            break
    if not key_found :
        raise AuthError({
            'Couldnot find RSA public key.'
        }, 401)
    else:
        try:
            payload = jwt.decode(
                token,
                {
                'use': rsa_public_key_data['use'],
                'kid': rsa_public_key_data['kid'],
                'kty': rsa_public_key_data['kty'],
                'e': rsa_public_key_data['e'],
                'n': rsa_public_key_data['n'],
                },
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
                algorithms=ALGORITHMS,
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError('JWT has expired', 401)

        except jwt.JWTClaimsError:
            raise AuthError("couldn't verify the user", 401)
        except Exception:
            raise AuthError({
                "Invalid Header"
            }, 401)


'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator