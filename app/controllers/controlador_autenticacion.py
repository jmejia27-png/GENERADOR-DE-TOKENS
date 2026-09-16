from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.services.servicio_autenticacion import ServicioAutenticacion, obtener_db, obtener_admin_actual
from app.schemas.esquema_autenticacion import SolicitudLogin, RespuestaLogin
from app.core.config_entorno import configuracion
from app.models.modelo_usuario import Usuario

router = APIRouter(prefix="/auth", tags=["Autenticación Admin"])


@router.post("/login", response_model=RespuestaLogin)
async def login(request: Request, datos: SolicitudLogin, db: Session = Depends(obtener_db)):
    """Login exclusivo para usuarios con rol admin. Emite un JWT de acceso al panel."""
    ip_cliente = request.client.host if request.client else "127.0.0.1"

    usuario = ServicioAutenticacion.autenticar_admin(
        db=db, username=datos.username, password=datos.password, ip_address=ip_cliente
    )

    if not usuario:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas o sin permisos de administrador"
        )

    token = ServicioAutenticacion.crear_token_acceso(usuario)

    return RespuestaLogin(
        access_token=token,
        expira_en_minutos=configuracion.JWT_EXPIRACION_MINUTOS,
        rol=usuario.rol.value
    )


@router.get("/me")
async def obtener_perfil_actual(admin_actual: Usuario = Depends(obtener_admin_actual)):
    """Endpoint de prueba: confirma que el token JWT es válido y devuelve el admin autenticado."""
    return {
        "id": str(admin_actual.id),
        "username": admin_actual.username,
        "rol": admin_actual.rol.value
    }