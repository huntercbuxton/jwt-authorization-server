from flask import Flask, jsonify, request, g, Response
from flask_cors import CORS
from flask_pydantic import validate
from authserver.model import GenerateJWTRequest, AuthJwts, ResponseDTO, ResponseStatus
from werkzeug.exceptions import BadRequest, Unauthorized, InternalServerError, Forbidden, NotFound, UnsupportedMediaType
import authserver.header_util as header_util  
from authserver.header_util import authenticate_bearer
import authserver.db as db 
import uuid
from authserver.log import setup_logger
from datetime import timedelta, timezone
import datetime 
import jwt 
import json 
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address 
from werkzeug.utils import import_string 
from authserver.config import appconfig, load_public_key, load_private_key # ConfigEnv, AppConfig

app = Flask(__name__)
CORS(app)


setup_logger(app.logger)

 
app.config.from_object(appconfig)
app.config['PRIVATE_KEY'] = load_private_key(appconfig.PRIVATE_KEY_PATH)
app.config['PUBLIC_KEY'] = load_public_key(appconfig.PUBLIC_KEY_PATH)
app.logger.info(f"{appconfig=}")
app.logger.info(f"{app.config=}")
 
app.logger.info(f"{app.config['CONSUMER_WHITELIST']=} \n{app.config['AUDIENCE_WHITELIST']=}")
limiter = Limiter(
    key_func=get_remote_address,# Identifies clients by their IP address
    app=app,
    storage_uri="redis://localhost:6379/0", 
    default_limits=["200 per day", f"{app.config['REQ_PER_HOUR_LIMIT']} per hour"], # Global limits applied to all routes
    headers_enabled=True  
)


@app.before_request
def validate_required_headers() -> None:  
    url_safe_exp = r"^[a-zA-Z0-9\-._~]+$"
    word_chars_exp = r"^\w+$"

    g.trace_id = header_util.validate_required_header('HBNS-TRACE-ID', regex=url_safe_exp)

    g.consumer_id = header_util.validate_required_header(header='HBNS-APP-ID', regex=word_chars_exp)
    if not g.consumer_id in app.config['CONSUMER_WHITELIST']: 
        raise Forbidden(description=f"'{g.consumer_id}' is not authorized to access this service")

@app.before_request
def log_request() -> None: 
    body = request.get_json() if request.is_json else None
    app.logger.info(f'REQUEST RECIEVED: {json.dumps({ 'path': request.path, 'headers': dict(request.headers), 'body': body }, indent=4)}')

@app.after_request
def logAfterRequest(response: Response) -> Response: 
    response.direct_passthrough = False
    body_data = response.get_json() if response.is_json else None
    app.logger.info(f'RESPONSE SENT: {json.dumps({ 'path': request.path, 'headers': dict(response.headers), 'body': body_data }, indent=4)}')
    return response
 
@app.errorhandler(UnsupportedMediaType)
@app.errorhandler(NotFound)
@app.errorhandler(Forbidden)
@app.errorhandler(Unauthorized)
@app.errorhandler(BadRequest)
@app.errorhandler(InternalServerError)
def handle_httpexception(e):
    app.logger.error(f"Mapping http {type(e).__name__ } exception class to error response", exc_info=True)
    return ResponseDTO.from_httpexception(e).model_dump(), e.code  

@app.errorhandler(429)
def ratelimit_handler(e):
    data = ResponseDTO(message=f"Rate limit exceeded: {e.description}", 
                            code="Too Many Requests", 
                            status=ResponseStatus.ERROR)
    return jsonify(data.model_dump()), 429

@app.errorhandler(Exception)
def fallback_exception_handler(e):
    app.logger.error("Mapping exception to error response", exc_info=True) 
    return ResponseDTO(message="Unhandled exception", code=500, status=ResponseStatus.ERROR), 500

@app.route("/generate", methods=["POST"]) 
@validate()
def generate_tokens(body: GenerateJWTRequest): 
    g.username, g.password = header_util.validate_basicauth_header() 
    account = db.find_account_by_username(g.username)

    if not account or not account['password'] == g.password:
        raise Unauthorized(description="Invalid login credentials.")

    if not g.consumer_id in account['authorize_clients']:
        raise Unauthorized(description=f"User not authorized for client app '{g.consumer_id}'")

    g.auth_ts = datetime.datetime.now(timezone.utc)  

    if body.timeout and body.timeout > app.config['ACCESS_TIMEOUT']:
        raise BadRequest(description=f"requested timeout cannot be greater than {app.config['ACCESS_TIMEOUT']}")
 
    for x in body.aud_values():
        if x not in app.config['AUDIENCE_WHITELIST']:
            raise Unauthorized(description=f"{x} is not a recognized audience")
        if x not in account['approved_aud']:
            raise Unauthorized(description=f"User not authorized for audience {x}")

    if body.admin and not account['is_admin']:
        raise Unauthorized(description="User not authorized for admin access")
    
    for p in body.projects:
        if not p in account['projects']:
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

    db.update_used_refresh_token(g.token)

    updated_claims = g.token_payload.copy()
    app.logger.debug(f"{updated_claims=}")
    updated_claims['iat'] = g.auth_ts
    updated_claims['exp'] = g.auth_ts + timedelta(minutes=app.config['ACCESS_TIMEOUT'])
    updated_claims['nbf'] = g.auth_ts
    updated_claims['jti'] = str(uuid.uuid4())
    access_token = jwt.encode(payload=updated_claims, key=app.config['PRIVATE_KEY'], algorithm="RS256")

    updated_claims['exp'] =  g.auth_ts + timedelta(minutes=app.config['REFRESH_TIMEOUT'])
    updated_claims['jti'] = str(uuid.uuid4())
    refresh_token = jwt.encode(payload=updated_claims, key=app.config['PRIVATE_KEY'], algorithm="RS256")
    db.add_refresh_token(g.token_payload['sub'], refresh_token, g.consumer_id)
    return jsonify(AuthJwts(access_token, refresh_token)._asdict())

 
@app.route("/revoke", methods=["POST"]) 
@header_util.authenticate_bearer
def revoke_refresh_token(): 
    g.auth_ts = datetime.datetime.now(timezone.utc) 
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
    return jsonify(ResponseDTO(message="refresh token revocation completed", status=ResponseStatus.SUCCESS).model_dump())