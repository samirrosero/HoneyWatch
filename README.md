# HoneyWatch

Honeypot educativo con dashboard en tiempo real, construido desde cero en Python
(socket + threading + sqlite3 + Flask). Simula servicios falsos y registra cada intento de conexión.

| Servicio | Puerto real | Puerto alterno | Qué captura |
|---|---|---|---|
| SSH   | 22   | 2222 | Banner del cliente (herramienta usada) |
| FTP   | 21   | 2121 | Usuario y contraseña en texto plano |
| HTTP (phpMyAdmin) | 80 | 8888 | Petición completa, User-Agent, login del formulario falso |
| WordPress (`/wp-login.php`, `/xmlrpc.php`) | 80 | 8888 | Usuario y contraseña, incluso cientos por petición vía xmlrpc |
| MySQL | 3306 | 3307 | Usuario y hash de la contraseña |

## Instalación

```
pip install -r requirements.txt
python main.py --clear
```

Dashboard: http://127.0.0.1:5000

Opciones: `--alt-ports` (si un puerto está ocupado), `--clear` (borra registros),
`--dashboard-host 0.0.0.0` (ver el dashboard desde otra PC).

## Demo

**Opción A: misma PC.** En otra terminal:

```
nmap -sV -p 21,22,80,3306 127.0.0.1
python tools/simular_ataque.py
ftp 127.0.0.1
```

**Opción B: dos PCs en la misma WiFi.** En la PC del honeypot, `ipconfig` para ver la IP
(ej. 192.168.1.50) y permitir Python en el Firewall de Windows (red privada).
Desde la otra PC:

```
nmap -sV -p 21,22,80,3306 192.168.1.50
ssh root@192.168.1.50
```

y abrir `http://192.168.1.50` en el navegador.

> `nmap -sS` (SYN scan) no completa la conexión TCP, así que el honeypot no lo ve.
> Usa `-sV` o `-sT`.

## Estructura

```
honeypot/logger.py      SQLite + geolocalización (ip-api.com) en segundo plano
honeypot/base_trap.py   Lógica común: socket, hilo por conexión, registro
honeypot/*_trap.py      Cada servicio falso (solo define cómo "conversa")
dashboard/app.py        API Flask: /api/stats, /api/attempts
main.py                 Arranca todos los traps + dashboard
tools/simular_ataque.py Atacante de prueba para la demo
```

## Aviso ético

Úsalo solo en tu propia red o en redes donde tengas autorización. Las IPs privadas (LAN) se
muestran como "Red local". La geolocalización solo funciona con IPs públicas.
