"""
HoneyWatch - mysql_trap.py
MySQL falso: envia un paquete de "handshake" real del protocolo MySQL,
lee la respuesta del cliente (que incluye el usuario) y responde
"Access denied". Asi `mysql -h IP -u root -p` y nmap -sV lo ven como MySQL real.
"""

import os
import struct

from honeypot.base_trap import BaseTrap, to_text

SERVER_VERSION = b"5.7.33-0ubuntu0.18.04.1"


def _packet(seq, payload: bytes) -> bytes:
    """Paquete MySQL: 3 bytes de longitud + 1 byte de secuencia + datos."""
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def _handshake() -> bytes:
    salt = os.urandom(20).replace(b"\x00", b"\x01")
    capabilities = 0xF7FF            # CLIENT_PROTOCOL_41, SECURE_CONNECTION, etc.
    payload = (
        b"\x0a"                                   # protocolo 10
        + SERVER_VERSION + b"\x00"
        + struct.pack("<I", 1337)                 # thread id
        + salt[:8] + b"\x00"
        + struct.pack("<H", capabilities)
        + b"\x21"                                 # charset utf8
        + struct.pack("<H", 0x0002)               # status: autocommit
        + struct.pack("<H", 0x81FF)               # capacidades (parte alta)
        + bytes([21])                             # longitud auth data
        + b"\x00" * 10
        + salt[8:] + b"\x00"
        + b"mysql_native_password\x00"
    )
    return _packet(0, payload)


def _access_denied(seq, user, ip) -> bytes:
    msg = f"Access denied for user '{user}'@'{ip}' (using password: YES)".encode()
    payload = b"\xff" + struct.pack("<H", 1045) + b"#28000" + msg
    return _packet(seq, payload)


class MySQLTrap(BaseTrap):
    service = "MySQL"

    def interact(self, conn, addr, result):
        data = b""
        try:
            conn.sendall(_handshake())
            data = conn.recv(4096)
            if len(data) < 4 + 32:
                return

            seq = data[3]
            body = data[4:]
            # HandshakeResponse41: caps(4) maxpkt(4) charset(1) filler(23) user\0 ...
            user_start = 32
            user_end = body.find(b"\x00", user_start)
            if user_end == -1:
                return
            user = body[user_start:user_end].decode("utf-8", "replace")
            result["username"] = user

            # La contrasena viaja como hash (SHA1 con salt), no en texto plano
            if user_end + 1 < len(body):
                pw_len = body[user_end + 1]
                pw_hash = body[user_end + 2: user_end + 2 + pw_len]
                result["password"] = f"[hash {pw_hash.hex()[:16]}...]" if pw_hash else "(vacia)"

            conn.sendall(_access_denied(seq + 1, user, addr[0]))
        finally:
            result["payload"] = to_text(data)[:1500]
