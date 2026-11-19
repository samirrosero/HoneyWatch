# HoneyWatch: herramientas, servicios y puertos

Honeypot educativo **de baja interacción**, escrito desde cero en Python. Imita servicios de red
reales para atraer atacantes, registra cada intento y lo muestra en un dashboard en tiempo real.

---

## 1. Herramientas y tecnologías utilizadas

### Lenguaje y librerías

| Herramienta | Tipo | Para qué se usa en el proyecto |
|---|---|---|
| **Python 3** | Lenguaje | Todo el proyecto |
| **socket** | Librería estándar | Abrir los puertos TCP y "conversar" con el atacante (servidores falsos) |
| **threading** | Librería estándar | Un hilo por servicio y un hilo por conexión, para atender varios atacantes a la vez |
| **sqlite3** | Librería estándar | Base de datos donde se guarda cada intento (`data/honeywatch.db`) |
| **struct** | Librería estándar | Construir los paquetes binarios del protocolo MySQL |
| **urllib** | Librería estándar | Consultar la geolocalización (ip-api.com) y enviar alertas a Telegram |
| **ipaddress** | Librería estándar | Distinguir IPs privadas (red local) de IPs públicas |
| **argparse** | Librería estándar | Opciones de línea de comandos (`--alt-ports`, `--clear`, etc.) |
| **queue** | Librería estándar | Cola de IPs pendientes de geolocalizar en segundo plano |
| **Flask** (>= 3.0) | Librería externa | Servidor web del dashboard y la API (`/api/stats`, `/api/attempts`) |

> **Flask** es la única dependencia externa (`requirements.txt`). Todo lo demás viene incluido en Python.

### Frontend (dashboard)

| Herramienta | Para qué se usa |
|---|---|
| **HTML + CSS** | Interfaz del dashboard (`dashboard/templates/index.html`, `dashboard/static/style.css`) |
| **JavaScript (fetch)** | Consulta la API cada **2 segundos** para actualizar los datos en tiempo real |
| **Chart.js 4.4.1** | Gráficas de intentos por servicio y en el tiempo |

### Servicios externos (gratuitos)

| Servicio | Para qué se usa | ¿Obligatorio? |
|---|---|---|
| **ip-api.com** | Obtener país, ciudad, coordenadas e ISP de las IPs públicas (máx. 45 consultas/min) | No (las IPs locales se muestran como "Red local") |
| **Telegram Bot API** | Enviar alertas al celular cuando se detecta fuerza bruta | No (se activa con `HW_TELEGRAM_TOKEN` y `HW_TELEGRAM_CHAT`) |

### Herramientas para probar o atacar en la demo

| Herramienta | Uso |
|---|---|
| **Nmap** | Escanear los puertos y ver cómo identifica los servicios falsos (`nmap -sV`) |
| **Cliente SSH** | `ssh root@IP` |
| **Cliente FTP** | `ftp IP` |
| **Cliente MySQL** | `mysql -h IP -u root -p` |
| **Navegador web** | Abrir `http://IP` (phpMyAdmin) o `http://IP/wp-login.php` (WordPress) y probar el login falso |
| **`tools/simular_ataque.py`** | Script propio que simula un bot de fuerza bruta contra los 5 servicios (incluye un ataque `xmlrpc.php` con 9 contraseñas en una sola petición) |

---

## 2. Servicios simulados y puertos

| Servicio | Puerto real | Puerto alterno (`--alt-ports`) | Se hace pasar por | Qué captura | Respuesta al atacante |
|---|---|---|---|---|---|
| **SSH** | 22 | 2222 | `OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` | Banner del cliente (revela la herramienta usada) e inicio del intercambio de claves | Cierra la conexión |
| **FTP** | 21 | 2121 | `vsFTPd 3.0.3` | Usuario y contraseña **en texto plano** y los comandos enviados | `530 Login incorrect.` |
| **HTTP** | 80 | 8888 | **phpMyAdmin 5.2.1** sobre `Apache/2.4.41 (Ubuntu)` y `PHP/7.4.3` (rutas `/`, `/phpmyadmin`, `/admin`...) | Ruta pedida, User-Agent, petición completa y usuario y contraseña del formulario | `#1045 - Acceso denegado` |
| **WordPress** | 80 | 8888 | **WordPress 6.x** en español, en el mismo Apache (`/wp-login.php`, `/wp-admin`, `/xmlrpc.php`) | Usuario y contraseña del login y **todas** las contraseñas de un ataque masivo por `xmlrpc.php` (`system.multicall`) | `Error: la contraseña ... no es correcta` / XML-RPC `403` |
| **MySQL** | 3306 | 3307 | `MySQL 5.7.33-0ubuntu0.18.04.1` | Usuario y **hash** de la contraseña (MySQL no la envía en texto plano) | `Access denied` (error 1045) |
| **Dashboard** | 5000 | 5000 | (servicio propio, no es trampa) | — | Panel web de monitoreo |

> **WordPress** comparte el puerto 80 con phpMyAdmin, como en un servidor real donde varias aplicaciones
> viven en el mismo Apache. La trampa decide cuál mostrar según la ruta pedida. Se eligió porque WordPress
> es el CMS más usado del mundo (~40 % de las webs) y por eso el más atacado por bots y herramientas como **WPScan**.
> `/wp-admin` redirige a `/wp-login.php` igual que el WordPress real.
>
> Si alguien se conecta y no envía datos, el intento se registra como **"posible escaneo de puertos"**.
>
> `nmap -sS` (SYN scan) **no** se detecta porque no completa la conexión TCP. Sí se detectan `-sV` y `-sT`.

---

## 3. Arquitectura del proyecto

```
HoneyWatch/
├── main.py                    Arranca los 4 servicios falsos + el dashboard
├── requirements.txt           Dependencias (flask)
├── honeypot/
│   ├── base_trap.py           Clase base: abre el socket y crea un hilo por conexión
│   ├── ssh_trap.py            SSH falso
│   ├── ftp_trap.py            FTP falso
│   ├── http_trap.py           phpMyAdmin + WordPress falsos (puerto 80)
│   ├── mysql_trap.py          MySQL falso (handshake binario real)
│   ├── logger.py              SQLite + geolocalización + detección de fuerza bruta
│   └── alerts.py              Alertas por Telegram
├── dashboard/
│   ├── app.py                 Flask: rutas /, /api/stats, /api/attempts
│   ├── templates/index.html   Interfaz del dashboard
│   └── static/style.css       Estilos
├── data/
│   └── honeywatch.db          Base de datos con los intentos
└── tools/
    └── simular_ataque.py      Atacante de prueba para la demo
```

### Flujo de un ataque

```
Atacante ──► Puerto (22/21/80/3306) ──► Trap (servicio falso)
                                           │
                                           ▼
                                  logger.py → SQLite
                                   │        │
                    ip-api.com ◄───┘        └───► ¿5+ intentos en 1 min? ──► Telegram
                                           │
                                           ▼
                           Dashboard Flask (se actualiza cada 2 s)
```

---

## 4. Base de datos (tabla `attempts`)

| Campo | Descripción |
|---|---|
| `id` | Identificador del intento |
| `timestamp` | Fecha y hora |
| `ip` / `src_port` | IP y puerto de origen del atacante |
| `dst_port` / `service` | Puerto y servicio atacado |
| `payload` | Lo que envió el atacante (máx. 4000 caracteres) |
| `username` / `password` | Credenciales capturadas |
| `country`, `country_code`, `city`, `lat`, `lon`, `isp` | Geolocalización (solo IPs públicas) |

---

## 5. Detección de fuerza bruta

| Parámetro | Valor |
|---|---|
| Umbral | **5 intentos** desde la misma IP |
| Ventana | **1 minuto** |
| Enfriamiento | Máximo 1 alerta cada **5 minutos** por IP |

---

## 6. Comandos de uso

```bash
pip install -r requirements.txt

python main.py                          # puertos reales (22, 21, 80, 3306)
python main.py --alt-ports              # puertos alternos (2222, 2121, 8888, 3307)
python main.py --clear                  # borra los registros anteriores
python main.py --dashboard-host 0.0.0.0 # ver el dashboard desde otra PC

python tools/simular_ataque.py              # simular ataques contra esta PC
python tools/simular_ataque.py 192.168.1.50 # contra otra PC de la red
```

Dashboard: **http://127.0.0.1:5000**

---

## 7. Aviso ético

Proyecto con fines **educativos**. Solo debe usarse en una red propia o con autorización. Los
servicios son falsos: nunca ejecutan comandos ni dan acceso real a ningún sistema.
