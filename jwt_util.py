import jwt
import logging
from flask import g, current_app
from datetime import timedelta, timezone
import datetime
from authserver.model import AuthJwts



def sign_jwt(claims):
    key = current_app.config['PRIVATE_KEY'] 
    return jwt.encode(payload=claims, key=key, algorithm="RS256")


def create_tokens(claims): 
    access_token = sign_jwt(claims)
    print(f"created access token with claims {claims}")
    claims['exp'] = claims['iat'] + timedelta(minutes=current_app.config['REFRESH_TIMEOUT'] )
    print(f"created refresh_token with claims {claims}")
    refresh_token = sign_jwt(claims) 
    # refresh_token_dao.save_new_refresh_token(claims['sub'], refresh_token) 
    return AuthJwts(access_token, refresh_token)
 

# def validate_jwt_signature(token, aud): 
#     key = load_public_key(appconfig.PUBLIC_KEY_FILE)
#     logger.info('aud passed to validate_jwt_ is ' + str(aud))
#     audience = aud
#     if not aud:
#         audience = None
#         logger.warning(f"The jwt is being validated with no aud claim. For now client has option to create token without an aud, and validate the same through the api, but this is not advisable for security")
#     return jwt.decode(jwt=token, key=key, audience=audience, algorithms=[ appconfig.ASYMMETRIC_SIGNING_ALGORITHM ])


 

