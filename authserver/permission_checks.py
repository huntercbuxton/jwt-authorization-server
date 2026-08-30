from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, UnsupportedMediaType
from flask import g, current_app
from authserver.model import GenerateJWTRequest
from datetime import timedelta, timezone
import datetime 
import uuid

 

def approve_projects_access(projects, account):
    for p in projects:
        if not p in account['projects']:
            raise Unauthorized(description=f"User is not authorized for project '{p}'")

def approve_single_audience(audience, account):
    if audience not in current_app.config['AUDIENCE_WHITELIST']:
        raise Unauthorized(description=f"{audience} is not a recognized audience")
    if audience not in account['approved_aud']:
        raise Unauthorized(description=f"User not authorized for audience {audience}")
 
def validate_custom_claims(custom_claims): 
    reserved_claims_conflicts = list((key for key in [ 'aud', 'exp', 'iss', 'iat', 'jti', 'sub', 'nbf'  ] if key in custom_claims))
    if reserved_claims_conflicts:
        raise BadRequest(description=f"custom_claims conflicts with reserved claim(s) {reserved_claims_conflicts}") 
    hbns_claims_conflicts = list((key for key in [ 'admin', 'projects', 'client_id' ] if key in custom_claims))
    if hbns_claims_conflicts:
        raise BadRequest(description=f"custom_claims conflicts with hbns claims(s) {hbns_claims_conflicts}")
   
def set_iat_and_exp(claims, timeout):
    now = datetime.datetime.now(timezone.utc)
    claims['iat'] = now
    claims['exp'] = now + timedelta(minutes=timeout)


 