from pydantic import BaseModel

class Vulnerability(BaseModel):
    name: str
    risk: str
    url: str