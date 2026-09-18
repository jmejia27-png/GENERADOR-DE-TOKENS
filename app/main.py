# app/main.py
from fastapi import FastAPI
from app.controllers import (
    controlador_generador_otp,
    controlador_autenticacion,
    controlador_usuarios,
    controlador_panel_admin  # NUEVO
)

app = FastAPI(
    title="Electronic Batch Record (EBR) - DEMO",
    description="Prototipo funcional de digitalización de Batch Record para Yobel/P&G",
    version="0.1.0"
)

app.include_router(controlador_generador_otp.router)
app.include_router(controlador_autenticacion.router)
app.include_router(controlador_usuarios.router)
app.include_router(controlador_panel_admin.router)   # NUEVO

@app.get("/")
async def inicio():
    return {
        "sistema": "EBR DEMO",
        "estado": "Servidor Uvicorn Operativo",
        "acceso_otp": "Ingrese a http://127.0.0.1:8000/otp/ para visualizar el Generador de Tokens",
        "acceso_admin": "Ingrese a http://127.0.0.1:8000/admin/panel para el Panel de Administración"
    }