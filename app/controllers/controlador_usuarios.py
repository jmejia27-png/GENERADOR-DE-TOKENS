from fastapi import APIRouter, Depends, HTTPException, Request, status, Query
from sqlalchemy.orm import Session
from typing import Optional

from app.services.servicio_usuario import ServicioUsuarios
from app.services.servicio_autenticacion import obtener_admin_actual, obtener_db
from app.schemas.esquema_usuario import UsuarioCrear, UsuarioActualizar, UsuarioRespuesta
from app.models.modelo_usuario import Usuario, RolUsuario

router = APIRouter(
    prefix="/admin/usuarios",
    tags=["Administración de Usuarios"],
    dependencies=[Depends(obtener_admin_actual)]  # protege TODAS las rutas de este router
)


@router.get("/", response_model=list[UsuarioRespuesta])
async def listar_usuarios(
    activo: Optional[bool] = Query(default=None),
    rol: Optional[RolUsuario] = Query(default=None),
    busqueda: Optional[str] = Query(default=None, description="Busca por username o email"),
    pagina: int = Query(default=1, ge=1),
    tamano_pagina: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(obtener_db)
):
    usuarios, _total = ServicioUsuarios.listar_usuarios(
        db, activo=activo, rol=rol, busqueda=busqueda, pagina=pagina, tamano_pagina=tamano_pagina
    )
    return usuarios


@router.get("/{usuario_id}", response_model=UsuarioRespuesta)
async def obtener_usuario(usuario_id: str, db: Session = Depends(obtener_db)):
    usuario = ServicioUsuarios.obtener_usuario_por_id(db, usuario_id)
    if not usuario:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return usuario


@router.post("/", response_model=UsuarioRespuesta, status_code=status.HTTP_201_CREATED)
async def crear_usuario(
    datos: UsuarioCrear,
    request: Request,
    db: Session = Depends(obtener_db),
    admin_actual: Usuario = Depends(obtener_admin_actual)
):
    ip_cliente = request.client.host if request.client else "127.0.0.1"
    try:
        return ServicioUsuarios.crear_usuario(db, datos, admin_actual, ip_cliente)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))


@router.patch("/{usuario_id}", response_model=UsuarioRespuesta)
async def actualizar_usuario(
    usuario_id: str,
    datos: UsuarioActualizar,
    request: Request,
    db: Session = Depends(obtener_db),
    admin_actual: Usuario = Depends(obtener_admin_actual)
):
    ip_cliente = request.client.host if request.client else "127.0.0.1"
    usuario = ServicioUsuarios.actualizar_usuario(db, usuario_id, datos, admin_actual, ip_cliente)
    if not usuario:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")
    return usuario