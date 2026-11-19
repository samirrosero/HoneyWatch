"""
HoneyWatch - ftp_trap.py
FTP falso (imita vsFTPd). Acepta USER/PASS, captura las credenciales y
siempre responde "Login incorrect".
"""

from honeypot.base_trap import BaseTrap, recv_line, to_text

MAX_COMMANDS = 20


class FTPTrap(BaseTrap):
    service = "FTP"

    def interact(self, conn, addr, result):
        log = []
        try:
            conn.sendall(b"220 (vsFTPd 3.0.3)\r\n")

            for _ in range(MAX_COMMANDS):
                line = recv_line(conn)
                if not line:
                    break
                text = to_text(line).strip()
                log.append(text)
                cmd, _, arg = text.partition(" ")
                cmd = cmd.upper()

                if cmd == "USER":
                    result["username"] = arg
                    conn.sendall(b"331 Please specify the password.\r\n")
                elif cmd == "PASS":
                    result["password"] = arg
                    conn.sendall(b"530 Login incorrect.\r\n")
                elif cmd == "SYST":
                    conn.sendall(b"215 UNIX Type: L8\r\n")
                elif cmd == "FEAT":
                    conn.sendall(b"211-Features:\r\n EPRT\r\n EPSV\r\n PASV\r\n UTF8\r\n211 End\r\n")
                elif cmd == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.sendall(b"530 Please login with USER and PASS.\r\n")
        finally:
            result["payload"] = "\n".join(log)
