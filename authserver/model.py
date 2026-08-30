from pydantic import BaseModel, EmailStr, Field, StrictBool, FutureDatetime
from typing import List, Dict, Optional, Annotated 

NonBlankPatternString = Annotated[str, Field( min_length=1, pattern=r'\S+')]

class HBNSClaims(BaseModel):
    admin: StrictBool | None = False 
    projects: List[str] | None = Field(description="list of projects for with access is requested", default=[])

class GenerateJWTRequest(BaseModel):
    """Model for validating token claims request data"""
    aud: str | List[str] | None = Field([], description="list of audiences pre-approved for the user")
    nbf: FutureDatetime | None = Field(description="(Optional) custom nbf value.", default=None)
    timeout: int | None = Field(description="(Optional) The time between nbf and exp", gt=10, lt=1441, default=None) 
    hbns_claims: HBNSClaims = Field(description="Claims required by HBNS platform service")
    custom_claims: Dict | None = Field(description="(Optional) custom claims defined by the client", default=None)


