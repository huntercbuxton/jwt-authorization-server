
from functools import wraps
from werkzeug.exceptions import BadRequest, Forbidden, Unauthorized, UnsupportedMediaType
from flask import Flask, request, abort, g, jsonify
import re
import base64 


def validate_required_header(header: str, regex=r'.*\S.*') -> str: 
    value = request.headers.get(header) 
    if not value:
        raise BadRequest(description=f"{header} is a required header")
    pattern = re.compile(regex)
    if not pattern.match(value):
        raise BadRequest(description=f"{header} must match '{regex}'") 
    return value


def validate_basicauth_header():
    value = validate_required_header('Authorization')
    try:
        scheme, encoded_credentials = value.split(" ", 1)
        if scheme.lower() != 'basic':
            raise Unauthorized(description=f"Authorization scheme not 'basic'") 
        decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
        # TODO: Use split(..., 1) to handle passwords with colons 
        username, password = decoded_credentials.split(":", 1)
    except ValueError as error:
        raise Unauthorized(description="invalid Authorization header format") from error
    except UnicodeDecodeError as error:
        raise Unauthorized(description=f"Failed to decode credentials; {error=}" ) from error 
    return username, password


def validate_bearer_header():
    value = validate_required_header('Authorization')
    try:
        scheme, token = value.split(" ", 1)
        if scheme.lower() != 'bearer':
            raise BadRequest(description=f"Authorization scheme not 'bearer'")
    except ValueError as error:
        raise BadRequest(description="invalid Authorization header format") from error
    pattern = re.compile(r"^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$")
    if not pattern.match(token):
        raise BadRequest(description="Invalid bearer token format")
    return token