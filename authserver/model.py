from pydantic import BaseModel, Field, StrictBool, field_validator, PositiveInt, FutureDatetime
from typing import List, Any, Dict, Optional, Annotated 
from collections import namedtuple
from enum import Enum 


NonBlankPatternString = Annotated[str, Field( min_length=1, pattern=r'\S+')]
 
class GenerateJWTRequest(BaseModel):
    """Model for validating token claims request data"""
    aud: str | List[str] = Field(description="list of audiences the user will access")
    timeout: PositiveInt | None = Field(description="(Optional) requested lifespan of the access token", default=None)
    admin: StrictBool = False 
    projects: List[str] = Field(description="list of projects for with access is requested", default=[])
    custom_claims: Dict[str, Any] = Field(description="(Optional) custom claims defined by the client", default={})

    @field_validator("custom_claims")
    @classmethod
    def validate_custom_claims(cls, value: str) -> str: 
        for key in value:
            if key in ['aud', 'exp', 'iss', 'iat', 'jti', 'sub', 'nbf']:
                raise ValueError(f"Invalid key '{key}' in custom_claims. Reserved claims are not allowed.") 
            if key in [ 'admin', 'projects'  ]: 
                raise ValueError(f"Invalid key '{key}' in custom_claims. Conflicts with the authorization server schema are not allowed.") 
        return value
    
    def aud_values(self):
        return [ self.aud ] if isinstance(self.aud, str) else self.aud

class ResponseStatus(str, Enum):
    SUCCESS = 'SUCCESS'
    ERROR = 'ERROR'
class ResponseDTO(BaseModel):
    status: ResponseStatus
    message: str 
    code: str | int | None = None

    @classmethod 
    def from_httpexception(cls, e):
        return cls(message=e.description, code=e.code, status=ResponseStatus.ERROR)

 
 
AuthJwts = namedtuple("AuthJwts", "access_token refresh_token")
