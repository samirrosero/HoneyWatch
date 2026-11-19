"""
HoneyWatch - ssh_trap.py
SSH falso: envia el banner de un OpenSSH real, registra el banner del cliente
y lo que envie despues (inicio del intercambio de claves), y cierra.
"""

from honeypot.base_trap import BaseTrap, to_text

SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"


class SSHTrap(BaseTrap):
    service = "SSH"

    def interact(self, conn, addr, result):
        conn.sendall(SSH_BANNER)

        data = b""
        try:
            while len(data) < 4096:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
                # Con el banner del cliente + su KEXINIT ya tenemos suficiente
                if b"\n" in data and len(data) > 64:
                    break
        finally:
            text = to_text(data)
            client_banner = text.split("\r\n")[0] if text.startswith("SSH-") else None
            if client_banner:
                result["payload"] = f"Cliente: {client_banner}\n{text[len(client_banner):][:1500]}"
            else:
                result["payload"] = text
