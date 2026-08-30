from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, UnsupportedMediaType
from flask import g, current_app
from authserver.model import GenerateJWTRequest


def authorize_admin_claim(admin, account):
    if admin and not account['is_admin']:
        raise Unauthorized(description="User not authorized for the admin-level access") 

def authorize_projects_claim(projects, account):
    if projects:
        for p in projects:
            if not p in account['projects']:
                raise Unauthorized(description=f"User is not authorized for project '{p}'")

def authorize_single_audience(audience, account):
    if audience not in current_app.config['AUDIENCE_WHITELIST']:
        raise Unauthorized(description=f"{audience} is not a recognized audience")
    if audience not in account['approved_aud']:
        raise Unauthorized(description=f"User not authorized for audience {audience}")

def authorize_aud_claim(audience, account):
    if isinstance(audience, list):
        for x in audience:
            authorize_single_audience(x, account)
    else:
        authorize_single_audience(audience, account)

  