from pydantic import BaseModel


class SolicitudLogin(BaseModel):
    username: str
    password: str


class RespuestaLogin(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expira_en_minutos: int
    rol: str