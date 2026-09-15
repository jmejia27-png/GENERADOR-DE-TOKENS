import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.models.modelo_usuario import Usuario
from app.models.modelo_token_otp import TokenOTP
from app.models.modelo_bitacora_auditoria import AuditTrail

ph = PasswordHasher()

class ServicioGeneradorOTP:

    @staticmethod
    def generar_otp_para_usuario(db: Session, username: str, password_plana: str, ip_address: str = "127.0.0.1") -> dict:
        # 1. Buscar Usuario activo
        usuario = db.query(Usuario).filter(Usuario.username == username, Usuario.activo == True).first()
        if not usuario:
            audit_fail = AuditTrail(
                evento="SOLICITUD_OTP_FALLIDA",
                modulo="GENERADOR_OTP",
                entidad="Usuario",
                entidad_id=username,
                accion="VALIDACION_CREDENCIALES",
                resultado="FALLIDO",
                ip_address=ip_address,
                datos_nuevos={"motivo": "Usuario inexistente o inactivo"}
            )
            db.add(audit_fail)
            db.commit()
            return {"exito": False, "mensaje": "Credenciales inválidas."}

        # 2. Validar Contraseña con Argon2
        try:
            ph.verify(usuario.password_hash, password_plana)
        except VerifyMismatchError:
            audit_fail = AuditTrail(
                usuario_id=usuario.id,
                evento="SOLICITUD_OTP_FALLIDA",
                modulo="GENERADOR_OTP",
                entidad="Usuario",
                entidad_id=str(usuario.id),
                accion="VALIDACION_CREDENCIALES",
                resultado="FALLIDO",
                ip_address=ip_address,
                datos_nuevos={"motivo": "Contraseña incorrecta"}
            )
            db.add(audit_fail)
            db.commit()
            return {"exito": False, "mensaje": "Credenciales inválidas."}

        # 3. Inactivar tokens OTP anteriores sin usar
        db.query(TokenOTP).filter(TokenOTP.usuario_id == usuario.id, TokenOTP.usado == False).update({"usado": True})

        # 4. Generar Código Criptográfico de 4 Dígitos (0000 - 9999)
        codigo_num = secrets.randbelow(10000)
        codigo_otp = f"{codigo_num:04d}"
        
        # Hash del token para almacenamiento seguro en la BD
        codigo_hash = ph.hash(codigo_otp)
        
        ahora = datetime.now(timezone.utc)
        expiracion = ahora + timedelta(seconds=60)

        nuevo_token = TokenOTP(
            usuario_id=usuario.id,
            codigo_hash=codigo_hash,
            expira_en=expiracion,
            usado=False
        )
        db.add(nuevo_token)

        # 5. Registrar Evento Exitoso en Audit Trail
        audit_success = AuditTrail(
            usuario_id=usuario.id,
            evento="GENERACION_OTP_EXITOSA",
            modulo="GENERADOR_OTP",
            entidad="TokenOTP",
            entidad_id=str(nuevo_token.id),
            accion="GENERAR_TOKEN",
            resultado="EXITOSO",
            ip_address=ip_address,
            datos_nuevos={"expira_en": expiracion.isoformat()}
        )
        db.add(audit_success)
        db.commit()

        return {
            "exito": True,
            "codigo_otp": codigo_otp,
            "expira_en_segundos": 60,
            "mensaje": "OTP generado correctamente."
        }