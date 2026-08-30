from flask import Flask, jsonify, request, g, Response
from flask_cors import CORS
from flask_pydantic import validate
from authserver.model import GenerateJWTRequest
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, UnsupportedMediaType
import authserver.header_util as header_util  
import authserver.db as db
import authserver.access_rules as access_rules


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
    print(f"{g.username=}\n{g.password=}")
    user_account = db.find_account_by_username(g.username)
    if not user_account or not user_account['password'] == g.password:
        raise Unauthorized(description="Invalid login credentials.")
    if not g.consumer_id in user_account['authorize_clients']:
        raise Unauthorized(description=f"User not authorized for client app '{g.consumer_id}'")

    access_rules.authorize_aud_claim(body.aud, user_account) 
    access_rules.authorize_admin_claim(body.hbns_claims.admin, user_account)
    access_rules.authorize_projects_claim(body.hbns_claims.projects, user_account)
    
    return jsonify({})


@app.route("/refresh", methods=["POST"]) 
def refresh_tokens():
    g.token = header_util.validate_bearer_header()
    print(f"{g.token}")
    return jsonify({})


@app.route("/revoke", methods=["POST"]) 
def revoke_tokens():
    g.token = header_util.validate_bearer_header()
    print(f"{g.token}")
    return jsonify({})

