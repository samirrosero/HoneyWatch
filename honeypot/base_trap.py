"""
HoneyWatch - base_trap.py
Clase base para todos los servidores falsos. Cada trap solo implementa
`interact()`, que define como "conversa" con el atacante.
"""

import socket
import sys
import threading
from datetime import datetime

from honeypot import logger


class BaseTrap(threading.Thread):
    service = "GENERIC"

    def __init__(self, port, host="0.0.0.0", timeout=15):
        super().__init__(daemon=True, name=f"{self.service}-trap")
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.ready = threading.Event()   # se activa cuando el bind termina (ok o error)
        self.error = None

    # ------------------------------------------------------------------
    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sys.platform == "win32":
                # Evita que otro proceso "robe" el puerto en Windows
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(50)
        except OSError as e:
            self.error = e
            self.ready.set()
            return

        self.ready.set()
        while True:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    # ------------------------------------------------------------------
    def _handle(self, conn, addr):
        ip, src_port = addr[0], addr[1]
        conn.settimeout(self.timeout)
        result = {"payload": "", "username": None, "password": None}

        try:
            self.interact(conn, addr, result)
        except (socket.timeout, ConnectionError, OSError):
            pass  # el atacante cerro o no envio nada: igual lo registramos
        except Exception as e:
            result["payload"] += f"\n[error interno: {e}]"
        finally:
            try:
                conn.close()
            except OSError:
                pass

        if not result["payload"].strip():
            result["payload"] = "(conexion sin datos - posible escaneo de puertos)"

        # Un trap puede cambiar la etiqueta por peticion (ej. HTTP -> WordPress)
        service = result.pop("service", None) or self.service
        # Un trap puede reportar la IP real (ej. visitante que llega por un tunel)
        ip = result.pop("ip", None) or ip
        logger.log_attempt(ip=ip, src_port=src_port, dst_port=self.port,
                           service=service, **result)

        creds = f"  user={result['username']!r} pass={result['password']!r}" \
            if result["username"] is not None else ""
        print(f"[{datetime.now():%H:%M:%S}] [{service:<5}] {ip}:{src_port} -> :{self.port}{creds}")

    # ------------------------------------------------------------------
    def interact(self, conn, addr, result):
        """Implementado por cada trap. Rellena result['payload'], ['username'], ['password']."""
        raise NotImplementedError

    def stop(self):
        if self.sock:
            self.sock.close()


# ----------------------------------------------------------------------
# Utilidades compartidas
# ----------------------------------------------------------------------
def to_text(data: bytes) -> str:
    """Convierte bytes a texto legible; lo no imprimible se muestra como \\xNN."""
    out = []
    for b in data:
        if 32 <= b < 127 or b in (9, 10, 13):
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def recv_line(conn, max_len=1024) -> bytes:
    """Lee hasta un salto de linea (para protocolos de texto como FTP)."""
    buf = b""
    while not buf.endswith(b"\n") and len(buf) < max_len:
        chunk = conn.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf
