import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import string

from app.models.modelo_usuario import Usuario
from app.models.modelo_token_otp import TokenOTP
from app.models.modelo_bitacora_auditoria import AuditTrail
from app.core.seguridad_cifrado import verificar_password
from app.services.servicio_auditoria import ServicioAuditoria

ph = PasswordHasher()  # instancia reutilizable para hashear el OTP

class ServicioGeneradorOTP:

    @staticmethod
    def generar_otp_para_usuario(db: Session, username: str, password: str, ip_address: str = "127.0.0.1"):
        """
        Valida las credenciales del usuario, genera un código OTP de 4 dígitos
        con vigencia de 60 segundos, lo guarda hasheado y registra la transacción
        en el Audit Trail.
        """
        # 1. Buscar usuario
        usuario = db.query(Usuario).filter(Usuario.username == username).first()
        if not usuario or not usuario.activo:
            ServicioAuditoria.registrar_evento(
                db=db,
                usuario_id=usuario.id if usuario else None,
                evento="GENERACION_OTP_FALLIDA",
                modulo="CU-00",
                entidad="tokens_otp",
                accion="GENERAR",
                resultado="ERROR_USUARIO_INVALIDO",
                ip_address=ip_address
            )
            return {"exito": False, "mensaje": "Credenciales inválidas o usuario inactivo"}

        # 2. Verificar contraseña con Argon2
        if not verificar_password(password, usuario.password_hash):
            ServicioAuditoria.registrar_evento(
                db=db,
                usuario_id=usuario.id,
                evento="GENERACION_OTP_FALLIDA",
                modulo="CU-00",
                entidad="tokens_otp",
                accion="GENERAR",
                resultado="ERROR_PASSWORD_INCORRECTA",
                ip_address=ip_address
            )
            return {"exito": False, "mensaje": "Credenciales inválidas"}

        # 3. Generar OTP numérico seguro de 4 dígitos (Vigencia 60 segundos)
        codigo_otp = ''.join(secrets.choice(string.digits) for _ in range(4))
        codigo_otp_hash = ph.hash(codigo_otp)  # se guarda el hash, no el valor real

        ahora = datetime.now(timezone.utc)
        expira_en = ahora + timedelta(seconds=60)

        # 4. Guardar en BD (usando el nombre real del campo: codigo_hash)
        nuevo_otp = TokenOTP(
            usuario_id=usuario.id,
            codigo_hash=codigo_otp_hash,
            creado_en=ahora,
            expira_en=expira_en,
            usado=False
        )
        db.add(nuevo_otp)
        db.commit()
        db.refresh(nuevo_otp)

        # 5. Registrar en Audit Trail
        ServicioAuditoria.registrar_evento(
            db=db,
            usuario_id=usuario.id,
            evento="GENERACION_OTP_EXITOSA",
            modulo="CU-00",
            entidad="tokens_otp",
            entidad_id=str(nuevo_otp.id),
            accion="GENERAR",
            resultado="EXITO",
            ip_address=ip_address
        )

        # El OTP en texto plano solo se devuelve UNA VEZ al usuario (ej. por SMS/email)
        # nunca se vuelve a recuperar de la base de datos
        return {
            "exito": True,
            "mensaje": "Token OTP generado con éxito",
            "codigo_otp": codigo_otp,
            "expira_en_segundos": 60
        }