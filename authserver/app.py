from flask import Flask, jsonify, request, g, Response
from flask_cors import CORS
from flask_pydantic import validate
from authserver.model import GenerateJWTRequest, AuthJwts
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, UnsupportedMediaType
import authserver.header_util as header_util  
import authserver.db as db 
import uuid
from datetime import timedelta, timezone
import datetime 
import jwt
import logging

app = Flask(__name__)
CORS(app)
 
app.config.from_object('authserver.config.DevelopmentConfig')
 
 
@app.before_request
def validate_required_headers() -> None:  
    url_safe_exp = r"^[a-zA-Z0-9\-._~]+$"
    word_chars_exp = r"^\w+$"

    g.trace_id = header_util.validate_required_header('HBNS-TRACE-ID', regex=url_safe_exp)

    g.consumer_id = header_util.validate_required_header(header='HBNS-APP-ID', regex=word_chars_exp)
    if not g.consumer_id in app.config['CONSUMER_WHITELIST']: 
        raise Forbidden(description=f"'{g.consumer_id}' is not authorized to access this service")

    
@app.route("/generate", methods=["POST"]) 
@validate()
def generate_tokens(body: GenerateJWTRequest): 
    g.username, g.password = header_util.validate_basicauth_header() 
    user_account = db.find_account_by_username(g.username)

    if not user_account or not user_account['password'] == g.password:
        raise Unauthorized(description="Invalid login credentials.")

    if not g.consumer_id in user_account['authorize_clients']:
        raise Unauthorized(description=f"User not authorized for client app '{g.consumer_id}'")

    g.auth_ts = datetime.datetime.now(timezone.utc)  

    if body.timeout and body.timeout > app.config['ACCESS_TIMEOUT']:
        raise BadRequest(description=f"requested timeout cannot be greater than {app.config['ACCESS_TIMEOUT']}")
 
    for x in body.aud_values():
        print(f"aud {x} to be authorized")
        if x not in app.config['AUDIENCE_WHITELIST']:
            raise Unauthorized(description=f"{x} is not a recognized audience")
        if x not in user_account['approved_aud']:
            raise Unauthorized(description=f"User not authorized for audience {x}")

    if body.admin and not user_account['is_admin']:
        raise Unauthorized(description="User not authorized for admin access")
    
    for p in body.projects:
        if not p in user_account['projects']:
            raise Unauthorized(description=f"User is not authorized for project '{p}'")
 
    claims = {
        'sub': g.username,
        'aud': body.aud,
        'iss': app.config['JWT_ISSUER'],
        'jti': str(uuid.uuid4()), 
        'iat': g.auth_ts,
        'exp': g.auth_ts + timedelta(minutes=body.timeout or app.config['ACCESS_TIMEOUT']),
        'nbf': g.auth_ts, 
        'projects': body.projects,
        'admin': body.admin,
    }
    claims.update(body.custom_claims)
    
    access_token = jwt.encode(payload=claims, key=app.config['PRIVATE_KEY'], algorithm="RS256")

    claims['exp'] = claims['iat'] + timedelta(minutes=app.config['REFRESH_TIMEOUT'])
    claims['jti'] = str(uuid.uuid4())  
    refresh_token = jwt.encode(payload=claims, key=app.config['PRIVATE_KEY'], algorithm="RS256")
    db.add_refresh_token(g.username, refresh_token, g.consumer_id)
    return jsonify(AuthJwts(access_token, refresh_token)._asdict())


@app.route("/refresh", methods=["POST"]) 
@header_util.authenticate_bearer
def refresh_tokens(): 
    g.auth_ts = datetime.datetime.now(timezone.utc)
    print(f"refresh {g.token_payload=}")
    token_record = db.get_refresh_token(g.token)
    # TODO: best practice is to authenticate the client via client_secret_basic,  private_key_jwt or similar
    if not token_record:
        raise Unauthorized(description=f"Token not registered")
    if token_record['used']:
        raise Unauthorized(description="Token has been used.")
    if token_record['revoked']:
        raise Unauthorized(description="Token has been revoked.")
    if not token_record['client_id'] == g.consumer_id:
        raise Unauthorized(description=f"Client {g.consumer_id} not authorized to use this token")

    updated_record = db.update_used_refresh_token(g.token)
    logging.debug(f"updated used refresh_token record: {updated_record=}")

    updated_claims = g.token_payload.copy()
    updated_claims['iat'] = g.auth_ts
    updated_claims['exp'] = g.auth_ts + timedelta(minutes=app.config['ACCESS_TIMEOUT'])
    updated_claims['nbf'] = g.auth_ts
    updated_claims['jti'] = str(uuid.uuid4())
    access_token = jwt.encode(payload=updated_claims, key=app.config['PRIVATE_KEY'], algorithm="RS256")

    updated_claims['exp'] =  g.auth_ts + timedelta(minutes=app.config['REFRESH_TIMEOUT'])
    updated_claims['jti'] = str(uuid.uuid4())
    refresh_token = jwt.encode(payload=updated_claims, key=app.config['PRIVATE_KEY'], algorithm="RS256")
    new_record = db.add_refresh_token(g.token_payload['sub'], refresh_token, g.consumer_id)
    return jsonify(AuthJwts(access_token, refresh_token)._asdict())

 
@app.route("/revoke", methods=["POST"]) 
@header_util.authenticate_bearer
def revoke_refresh_token(): 
    g.auth_ts = datetime.datetime.now(timezone.utc) 
    print(f"refresh {g.token_payload=}")
    token_record = db.get_refresh_token(g.token)
    # TODO: best practice is to authenticate the client via client_secret_basic,  private_key_jwt or similar
    if not token_record:
        raise Unauthorized(description=f"Token not registered")
    if token_record['used']:
        raise Unauthorized(description="Token has been used.")
    if token_record['revoked']:
        raise Unauthorized(description="Token has been revoked.")
    if not token_record['client_id'] == g.consumer_id:
        raise Unauthorized(description=f"Client {g.consumer_id} not authorized to use this token")

    db.update_revoked_refresh_token(g.token)
    return jsonify({ "msg": "revocation success" })