from fastapi import FastAPI
from app.controllers import controlador_generador_otp

app = FastAPI(
    title="Electronic Batch Record (EBR) - DEMO",
    description="Prototipo funcional de digitalización de Batch Record para Yobel/P&G",
    version="0.1.0"
)

# Inclusión del router del Generador OTP
app.include_router(controlador_generador_otp.router)

@app.get("/")
async def inicio():
    return {
        "sistema": "EBR DEMO",
        "estado": "Servidor Uvicorn Operativo",
        "acceso_otp": "Ingrese a http://127.0.0.1:8000/otp/ para visualizar el Generador de Tokens"
    }