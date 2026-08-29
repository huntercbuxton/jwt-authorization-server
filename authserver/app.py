from flask import Flask, jsonify, request, g, Response
from flask_cors import CORS
from flask_pydantic import validate
from authserver.model import GenerateJWTRequest
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, UnsupportedMediaType
import authserver.utils as utils  

app = Flask(__name__)
CORS(app)
 
app.config.from_object('authserver.config.DevelopmentConfig')
 
 
@app.before_request
def validate_required_headers() -> None:  
    url_safe_exp = r"^[a-zA-Z0-9\-._~]+$"
    word_chars_exp = r"^\w+$"

    utils.validate_required_header('Authorization')
    g.trace_id = utils.validate_required_header('HBNS-TRACE-ID', regex=url_safe_exp)
    g.consumer_id = utils.validate_required_header(header='HBNS-APP-ID', regex=word_chars_exp)
    if not g.consumer_id in app.config['CONSUMER_WHITELIST']: 
        raise Forbidden(description=f"'{g.consumer_id}' is not authorized to access this service")

    
@app.route("/generate", methods=["POST"]) 
@validate()
def generate_tokens(body: GenerateJWTRequest):
    print(f"{g.consumer_id=}\n{g.trace_id=}")
    g.username, g.password = utils.validate_basicauth_header()
    print(f"{g.username=}\n{g.password=}")
    return jsonify({})


@app.route("/refresh", methods=["POST"]) 
def refresh_tokens():
    g.token = utils.validate_bearer_header()
    print(f"{g.token}")
    return jsonify({})


@app.route("/revoke", methods=["POST"]) 
def revoke_tokens():
    g.token = utils.validate_bearer_header()
    print(f"{g.token}")
    return jsonify({})

