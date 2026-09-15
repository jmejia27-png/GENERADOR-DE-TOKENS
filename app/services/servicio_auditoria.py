import logging
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session

# Configuración básica de logs en consola
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("audit_trail")

class ServicioAuditoria:

    @staticmethod
    def registrar_evento(
        db: Optional[Session],
        evento: str,
        modulo: str,
        accion: str,
        resultado: str,
        usuario_id: Optional[str] = None,
        entidad: Optional[str] = None,
        entidad_id: Optional[str] = None,
        ip_address: str = "127.0.0.1",
        datos_anteriores: Optional[Dict[str, Any]] = None,
        datos_nuevos: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Registra eventos de auditoría transversalmente en la aplicación.
        """
        logger.info(f"[AUDIT] [{modulo}] {evento} - Accion: {accion} - Resultado: {resultado} - User: {usuario_id}")
        
        # En etapas siguientes se persiste directamente en la entidad ORM de audit_trail en PostgreSQL
        return True