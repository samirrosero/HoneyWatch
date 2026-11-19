# HoneyWatch: documentación técnica del código

Este documento explica **cada archivo, clase, función y constante** del proyecto: qué hace, qué recibe,
qué devuelve y por qué está hecho así. Para las herramientas, puertos y servicios consulta
[`HERRAMIENTAS.md`](HERRAMIENTAS.md), y para instalarlo y usarlo, [`README.md`](README.md).

---

## Índice

1. [Visión general](#1-visión-general)
2. [`main.py`: punto de entrada](#2-mainpy-punto-de-entrada)
3. [`honeypot/base_trap.py`: clase base de las trampas](#3-honeypotbase_trappy-clase-base-de-las-trampas)
4. [`honeypot/ssh_trap.py`: SSH falso](#4-honeypotssh_trappy-ssh-falso)
5. [`honeypot/ftp_trap.py`: FTP falso](#5-honeypotftp_trappy-ftp-falso)
6. [`honeypot/http_trap.py`: phpMyAdmin y WordPress falsos](#6-honeypothttp_trappy-phpmyadmin-y-wordpress-falsos)
7. [`honeypot/mysql_trap.py`: MySQL falso](#7-honeypotmysql_trappy-mysql-falso)
8. [`honeypot/logger.py`: base de datos y geolocalización](#8-honeypotloggerpy-base-de-datos-y-geolocalización)
9. [`honeypot/alerts.py`: alertas por Telegram](#9-honeypotalertspy-alertas-por-telegram)
10. [`dashboard/app.py`: API web con Flask](#10-dashboardapppy-api-web-con-flask)
11. [`dashboard/templates/index.html`: interfaz del dashboard](#11-dashboardtemplatesindexhtml-interfaz-del-dashboard)
12. [`tools/simular_ataque.py`: atacante de prueba](#12-toolssimular_ataquepy-atacante-de-prueba)
13. [Concurrencia: cómo conviven los hilos](#13-concurrencia-cómo-conviven-los-hilos)
14. [Seguridad del propio honeypot](#14-seguridad-del-propio-honeypot)
15. [Cómo agregar una trampa nueva](#15-cómo-agregar-una-trampa-nueva)

---

## 1. Visión general

HoneyWatch es un **honeypot de baja interacción**: abre puertos de red que imitan servicios reales
(SSH, FTP, HTTP y MySQL), conversa con el atacante solo lo necesario para capturar información
(herramienta usada, usuario, contraseña, ruta pedida) y **siempre** le niega el acceso. Detrás no hay
ningún servicio real.

### Flujo completo de un ataque

```
1. El atacante se conecta a un puerto (ej. 21)
        │
2. BaseTrap.run() acepta la conexión  ──► crea un hilo nuevo: BaseTrap._handle()
        │
3. _handle() llama a interact() de la trampa concreta (FTPTrap.interact)
        │      └─ la trampa conversa con el atacante y llena el diccionario `result`
        │
4. _handle() llama a logger.log_attempt()
        │      ├─ INSERT en SQLite (tabla attempts)
        │      ├─ mete la IP en la cola de geolocalización  ──► hilo geo-worker ──► ip-api.com ──► UPDATE
        │      └─ _check_bruteforce() ──► si hay 5+ intentos en 1 min ──► alerts.notify() ──► Telegram
        │
5. El navegador del dashboard pide /api/stats y /api/attempts cada 2 segundos y redibuja
```

### Dependencias entre módulos

```
main.py ──► honeypot/*_trap.py ──► honeypot/base_trap.py ──► honeypot/logger.py ──► honeypot/alerts.py
   │
   └──────► dashboard/app.py ──────────────────────────────► honeypot/logger.py
```

---

## 2. `main.py`: punto de entrada

Arranca todas las trampas (una por hilo) y después el servidor web del dashboard.

### Constante `TRAPS`

```python
TRAPS = [
    (SSHTrap, 22, 2222),
    (FTPTrap, 21, 2121),
    (HTTPTrap, 80, 8888),
    (MySQLTrap, 3306, 3307),
]
```

Lista de tuplas `(clase, puerto_real, puerto_alterno)`. El puerto alterno se usa con `--alt-ports`,
útil cuando el puerto real ya está ocupado (por ejemplo, si Windows ya tiene algo en el 80) o cuando
no hay permisos para puertos bajos (en Linux, los puertos < 1024 requieren `root`).

Para agregar un servicio nuevo basta con añadir una tupla aquí (ver [sección 15](#15-cómo-agregar-una-trampa-nueva)).

### Constante `BANNER`

Texto ASCII que se imprime al arrancar. Es puramente decorativo.

### Función `main()`

**Qué hace, paso a paso:**

1. **Lee los argumentos** de la línea de comandos con `argparse`:

   | Argumento | Por defecto | Efecto |
   |---|---|---|
   | `--alt-ports` | apagado | Usa los puertos alternos (2222, 2121, 8888, 3307) |
   | `--host` | `0.0.0.0` | Interfaz donde escuchan las trampas. `0.0.0.0` = todas las tarjetas de red |
   | `--dashboard-host` | `127.0.0.1` | Interfaz del dashboard. Por defecto **solo esta PC** lo puede ver |
   | `--dashboard-port` | `5000` | Puerto del dashboard |
   | `--clear` | apagado | Borra los registros anteriores antes de empezar |

2. **Prepara la base de datos** con `logger.init_db()` y, si se pidió, la vacía con `logger.clear_db()`.

3. **Arranca cada trampa:**
   ```python
   trap = trap_cls(port=port, host=args.host)
   trap.start()                 # lanza el hilo (ejecuta BaseTrap.run)
   trap.ready.wait(timeout=3)   # espera a que el bind termine, bien o mal
   ```
   El `ready.wait()` es importante: sin él, `main()` revisaría `trap.error` antes de que el hilo haya
   intentado abrir el puerto, y no sabría si falló.

4. **Construye la lista `status`**, con un diccionario `{service, port, active}` por trampa. El
   dashboard la usa para pintar los indicadores verdes/rojos de la parte superior. Como WordPress vive
   en el mismo puerto que HTTP, se agrega una entrada extra `WordPress` con el mismo estado que HTTP.

5. Si **ninguna** trampa arrancó, sugiere `--alt-ports` y termina.

6. Informa si las **alertas de Telegram** están configuradas (`alerts.is_configured()`).

7. **Silencia los logs de Flask/Werkzeug** (`setLevel(logging.ERROR)`) para que en la consola solo se
   vean los ataques, no cada petición del dashboard.

8. **Arranca Flask** con `app.run(..., threaded=True)`. Esta llamada **bloquea** el hilo principal
   hasta que se presiona `Ctrl+C`. Las trampas siguen funcionando porque corren en hilos `daemon`.

---

## 3. `honeypot/base_trap.py`: clase base de las trampas

Contiene toda la lógica común: abrir el socket, aceptar conexiones, crear un hilo por atacante y
registrar el resultado. Cada trampa concreta **solo** implementa el método `interact()`.

Este es el patrón de diseño **Template Method**: la clase base define el "esqueleto" del algoritmo
(`run` → `_handle` → `interact` → `log_attempt`) y las subclases rellenan el paso variable (`interact`).

### Clase `BaseTrap(threading.Thread)`

Hereda de `threading.Thread`, así que **cada trampa es un hilo**. Llamar a `trap.start()` ejecuta
`trap.run()` en paralelo.

#### Atributo de clase `service`

```python
service = "GENERIC"
```

Nombre del servicio que se guarda en la base de datos. Cada subclase lo sobreescribe
(`"SSH"`, `"FTP"`, `"HTTP"`, `"MySQL"`).

#### `__init__(self, port, host="0.0.0.0", timeout=15)`

| Parámetro | Significado |
|---|---|
| `port` | Puerto TCP donde escuchará la trampa |
| `host` | Interfaz de red. `0.0.0.0` = todas |
| `timeout` | Segundos máximos que se espera al atacante sin que envíe nada. Evita que una conexión colgada ocupe un hilo para siempre |

Atributos que crea:

| Atributo | Tipo | Para qué |
|---|---|---|
| `self.sock` | `socket` o `None` | El socket que escucha |
| `self.ready` | `threading.Event` | Se activa cuando el `bind` termina (con éxito o con error). `main.py` lo espera |
| `self.error` | `OSError` o `None` | Si el puerto no se pudo abrir, aquí queda el motivo |

`daemon=True` hace que el hilo muera automáticamente cuando termina el programa principal.

#### `run(self)`

Se ejecuta en el hilo de la trampa.

1. **Crea un socket TCP** (`AF_INET` = IPv4, `SOCK_STREAM` = TCP).
2. **Configura la reutilización del puerto:**
   - En **Windows** usa `SO_EXCLUSIVEADDRUSE`, que impide que otro programa "robe" el puerto mientras
     HoneyWatch lo usa. En Windows, `SO_REUSEADDR` permite justo lo contrario, por eso no se usa.
   - En **Linux/macOS** usa `SO_REUSEADDR`, que permite reabrir el puerto inmediatamente después de
     cerrar el programa (sin esperar el estado `TIME_WAIT` de TCP).
3. `bind((host, port))` reserva el puerto y `listen(50)` lo pone a escuchar con una cola de hasta
   50 conexiones pendientes.
4. Si algo falla (puerto ocupado, sin permisos), guarda el error en `self.error`, activa `ready` y
   termina.
5. **Bucle infinito:** `accept()` espera a un atacante. Por cada conexión crea un **hilo nuevo** que
   ejecuta `_handle()`. Así diez atacantes simultáneos no se bloquean entre sí.

#### `_handle(self, conn, addr)`

Atiende a **un** atacante. Se ejecuta en su propio hilo.

| Parámetro | Significado |
|---|---|
| `conn` | Socket conectado con el atacante |
| `addr` | Tupla `(ip, puerto_origen)` del atacante |

1. Aplica el `timeout` al socket.
2. Crea el diccionario `result = {"payload": "", "username": None, "password": None}` que la trampa
   irá llenando.
3. Llama a `self.interact(conn, addr, result)`.
4. **Manejo de errores:**
   - `socket.timeout`, `ConnectionError`, `OSError`: el atacante cerró o no envió nada. Es normal y se
     ignora, **pero el intento se registra igual**.
   - Cualquier otra excepción: se anota en el payload como `[error interno: ...]` para depurar sin
     que el hilo se caiga.
5. Cierra la conexión en el bloque `finally` (siempre se ejecuta).
6. Si el payload quedó vacío, lo marca como `(conexion sin datos - posible escaneo de puertos)`.
   Es lo que pasa con `nmap -sT`: abre la conexión y la cierra sin enviar nada.
7. **Permite que la trampa cambie dos datos** antes de guardar:
   - `result["service"]`: la trampa HTTP lo pone en `"WordPress"` cuando la ruta es de WordPress.
   - `result["ip"]`: la trampa HTTP pone la IP real del visitante cuando llega por el túnel de Cloudflare.

   Se usan con `pop()` para sacarlos del diccionario, porque `log_attempt(**result)` no acepta esas claves.
8. Llama a `logger.log_attempt(...)` y lo imprime en consola, por ejemplo:
   ```
   [14:10:27] [FTP  ] 192.168.0.149:51234 -> :21  user='root' pass='toor'
   ```

#### `interact(self, conn, addr, result)`

Método **abstracto**: en la clase base lanza `NotImplementedError`. Cada subclase lo implementa con la
"conversación" de su protocolo y debe rellenar `result["payload"]`, `result["username"]` y
`result["password"]`.

#### `stop(self)`

Cierra el socket que escucha. Al cerrarse, `accept()` lanza `OSError` y el bucle de `run()` termina.

### Funciones auxiliares

#### `to_text(data: bytes) -> str`

Convierte los bytes recibidos en texto **legible y seguro** para guardar y mostrar.

- Los caracteres imprimibles (ASCII 32 a 126), el tabulador y los saltos de línea se dejan igual.
- Todo lo demás se muestra como `\xNN`. Por ejemplo, el byte `0x00` se guarda como `\x00`.

Es necesario porque los protocolos binarios (SSH, MySQL) envían bytes que no son texto, y guardarlos
crudos rompería la base de datos o la pantalla.

#### `recv_line(conn, max_len=1024) -> bytes`

Lee del socket **byte por byte** hasta encontrar un salto de línea (`\n`), hasta que el atacante cierre,
o hasta `max_len` bytes. Se usa en FTP, donde cada comando es una línea (`USER root\r\n`).

`max_len` evita que un atacante envíe una "línea" infinita para agotar la memoria.

---

## 4. `honeypot/ssh_trap.py`: SSH falso

### Constante `SSH_BANNER`

```python
SSH_BANNER = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
```

En el protocolo SSH, lo **primero** que hace el servidor es enviar una línea que dice qué software es.
Este banner imita a un Ubuntu 20.04 real. Es exactamente lo que `nmap -sV` lee para identificar el servicio.

### Clase `SSHTrap(BaseTrap)`

`service = "SSH"`

#### `interact(self, conn, addr, result)`

1. Envía el banner falso.
2. Recibe datos en bloques de 1024 bytes, hasta 4096 en total. Se detiene cuando ya tiene una línea
   completa y más de 64 bytes, que es suficiente para el **banner del cliente** y el inicio del
   intercambio de claves (`KEXINIT`).
3. Si los datos empiezan con `SSH-`, separa la primera línea como **banner del cliente**. Esa línea
   revela la herramienta del atacante, por ejemplo:
   - `SSH-2.0-OpenSSH_9.6` → cliente SSH normal (una persona)
   - `SSH-2.0-libssh2_1.10.0` → librería usada por bots de fuerza bruta
   - `SSH-2.0-Go` → herramienta automatizada escrita en Go
4. Guarda en el payload `Cliente: <banner>` seguido del resto de los datos (máximo 1500 caracteres).

**¿Por qué no captura la contraseña?** En SSH, la contraseña viaja **cifrada**, después del intercambio
de claves. Capturarla requeriría implementar toda la criptografía de SSH (lo que hacen honeypots como
Cowrie). Esta trampa se queda en el banner, que ya identifica la herramienta.

---

## 5. `honeypot/ftp_trap.py`: FTP falso

### Constante `MAX_COMMANDS = 20`

Máximo de comandos que se aceptan por conexión. Evita que un atacante mantenga la conexión abierta
indefinidamente.

### Clase `FTPTrap(BaseTrap)`

`service = "FTP"`

#### `interact(self, conn, addr, result)`

FTP es un protocolo de **texto**: el cliente envía comandos de una línea y el servidor responde con un
código de 3 dígitos.

1. Envía el saludo `220 (vsFTPd 3.0.3)`, que imita al servidor FTP más común en Linux.
2. Lee hasta 20 líneas con `recv_line()` y responde a cada comando:

   | Comando del atacante | Respuesta falsa | Qué se captura |
   |---|---|---|
   | `USER root` | `331 Please specify the password.` | `username = "root"` |
   | `PASS toor` | `530 Login incorrect.` | `password = "toor"` |
   | `SYST` | `215 UNIX Type: L8` | Se finge ser Unix |
   | `FEAT` | Lista de funciones | Se finge un servidor completo |
   | `QUIT` | `221 Goodbye.` | Termina la conversación |
   | Cualquier otro | `530 Please login with USER and PASS.` | — |

3. Guarda en el payload todos los comandos recibidos, uno por línea.

**Dato para la presentación:** FTP envía la contraseña **en texto plano**, sin cifrar. Por eso esta
trampa la captura completa. Es una de las razones por las que FTP se considera inseguro.

---

## 6. `honeypot/http_trap.py`: phpMyAdmin y WordPress falsos

Una sola trampa en el puerto 80 que decide **según la ruta pedida** qué aplicación imitar, igual que un
servidor Apache real donde conviven varias aplicaciones.

### Constantes

| Constante | Contenido |
|---|---|
| `SERVER_HEADER` | `"Apache/2.4.41 (Ubuntu)"`: cabecera `Server` de cada respuesta |
| `POWERED_BY` | `"PHP/7.4.3"`: cabecera `X-Powered-By` |
| `PMA_PAGE` | HTML de la pantalla de login de phpMyAdmin 5.2. Tiene un marcador `{error}` |
| `WP_PAGE` | HTML del login de WordPress 6.x en español. Tiene los marcadores `{error}` y `{user}` |
| `XMLRPC_FAULT` | Respuesta XML de error de WordPress: código `403`, "Nombre de usuario o contraseña incorrectos." |
| `WP_PATTERN` | Expresión regular que reconoce rutas de WordPress: `wp-login.php`, `/wp-admin`, `xmlrpc.php`, `/wordpress`, `/wp/`, `/wp-content`, `/wp-includes` |
| `XMLRPC_METHOD` | Expresión regular que reconoce nombres de métodos XML-RPC (`wp.getUsersBlogs`, `system.multicall`...) para no confundirlos con usuarios o contraseñas |

Las páginas están recreadas **solo con CSS**, sin imágenes externas: así se ven reales sin depender de
internet ni copiar archivos de esos proyectos.

### Clase `HTTPTrap(BaseTrap)`

`service = "HTTP"` (cambia a `"WordPress"` por petición cuando corresponde).

#### `interact(self, conn, addr, result)`

Hace de "router": lee la petición HTTP y la envía a la trampa adecuada.

1. **Lee las cabeceras** hasta encontrar la línea vacía `\r\n\r\n` que las separa del cuerpo
   (máximo 16 KB).
2. **Separa** la primera línea (`POST /wp-login.php HTTP/1.1`), las cabeceras (en un diccionario con
   las claves en minúscula) y el cuerpo.
3. **Lee el cuerpo completo** según `Content-Length` (máximo 16 KB). Si la cabecera trae basura, usa 0.
4. **IP real por el túnel de Cloudflare:** si existe la cabecera `CF-Connecting-IP`, la conexión viene
   de `127.0.0.1` (o sea, de `cloudflared` corriendo en esta misma PC) y el valor es una IP válida,
   la guarda en `result["ip"]`. Si la conexión viene de cualquier otro lado, **ignora la cabecera**:
   así un atacante no puede inventarse una IP falsa.
5. Extrae el **método** (`GET`, `POST`) y la **ruta** (sin la parte `?...`).
6. Si la ruta coincide con `WP_PATTERN` → `result["service"] = "WordPress"` y llama a `_wordpress()`.
   Si no → llama a `_phpmyadmin()`.
7. En el `finally` guarda en el payload la petición completa, precedida del resumen que devuelva la
   trampa de WordPress (si lo hay).

#### `_phpmyadmin(self, conn, method, body, result)`

1. Si es un `POST` con cuerpo, lo decodifica como formulario (`parse_qs`).
2. Busca el usuario en los campos `pma_username`, `username` o `user`, y la contraseña en
   `pma_password`, `password` o `pass`. Así captura tanto el formulario falso como bots que envían
   nombres de campo genéricos.
3. Arma el mismo error que muestra phpMyAdmin real:
   `#1045 - Acceso denegado para el usuario 'root'@'localhost' (using password: YES)`.
4. Envía la página con `_send()`.

#### `_wordpress(self, conn, method, path, body, result) -> str`

Imita tres comportamientos de WordPress:

| Ruta | Comportamiento |
|---|---|
| `/wp-admin...` | Responde `302 Found` redirigiendo a `/wp-login.php?redirect_to=...&reauth=1`, igual que WordPress cuando no hay sesión |
| `/xmlrpc.php` con `GET` | Responde `405` con el texto exacto de WordPress: `XML-RPC server accepts POST requests only.` |
| `/xmlrpc.php` con `POST` | Llama a `_xmlrpc()` |
| `/wp-login.php` y el resto | Muestra el login. Si es `POST`, captura `log` (usuario) y `pwd` (contraseña) y muestra el error de WordPress en español |

El login también envía la cookie `wordpress_test_cookie=WP%20Cookie%20check`, que WordPress real pone
para comprobar que el navegador acepta cookies. Es un detalle más para que el engaño sea convincente.

Devuelve un texto de resumen (vacío salvo en XML-RPC).

#### `_xmlrpc(self, conn, body, result) -> str`

`xmlrpc.php` es la API antigua de WordPress. Los atacantes la prefieren porque con el método
`system.multicall` pueden probar **cientos de contraseñas en una sola petición**, esquivando los
límites de intentos del login normal.

1. Decodifica el cuerpo XML.
2. Extrae el nombre del método (`<methodName>`).
3. Extrae todos los valores "hoja" (`<value>texto</value>` o `<value><string>texto</string></value>`)
   con una expresión regular y les quita el escape HTML.
4. Descarta los que son nombres de métodos (usando `XMLRPC_METHOD`).
5. Agrupa los valores restantes **de dos en dos** como pares `(usuario, contraseña)`.
6. Guarda el primer par en `username` y `password`.
7. Responde siempre `XMLRPC_FAULT` (acceso denegado).
8. Devuelve un resumen. Si hubo más de un par, lista hasta 30:
   ```
   [XML-RPC] metodo: system.multicall
   [XML-RPC] 9 contrasenas probadas en UNA sola peticion:
      admin / root
      admin / admin
      ...
   ```

**¿Por qué expresiones regulares y no un parser XML?** Los parsers XML pueden ser vulnerables a
ataques como "billion laughs" (un XML que se expande hasta agotar la memoria). Las expresiones
regulares sobre un texto de máximo 16 KB no tienen ese riesgo.

### Funciones auxiliares

#### `_send(conn, status, content, ctype="text/html; charset=UTF-8", extra=None)`

Arma y envía una respuesta HTTP completa:

```
HTTP/1.1 <status>
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Type: <ctype>
Content-Length: <tamaño>
<cabeceras extra>
Connection: close

<contenido>
```

`extra` es un diccionario de cabeceras adicionales (por ejemplo, `Location` para redirecciones o
`Set-Cookie`). `Connection: close` indica que se cerrará la conexión después de responder.

#### `_valid_ip(text) -> bool`

Devuelve `True` si el texto es una IP válida (IPv4 o IPv6). Usa `ipaddress.ip_address()`.

#### `_is_loopback(ip) -> bool`

Devuelve `True` si la IP es de "loopback" (`127.0.0.1` o `::1`), es decir, si la conexión viene de
esta misma PC.

#### `_first(form, *names)`

Recibe el formulario decodificado (`{"campo": ["valor"]}`) y una lista de nombres posibles. Devuelve el
valor del **primer** campo que exista, o `None`.

#### `_esc(text)`

Escapa `&`, `<`, `>` y `"` antes de insertar texto del atacante en el HTML. Evita que un atacante
escriba como usuario algo como `<script>...</script>` y ejecute código en la página de respuesta (XSS).

---

## 7. `honeypot/mysql_trap.py`: MySQL falso

MySQL usa un protocolo **binario**. Esta trampa implementa lo suficiente para que el cliente oficial
(`mysql -h IP -u root -p`) y `nmap -sV` crean que es un MySQL real.

### Constante `SERVER_VERSION`

`b"5.7.33-0ubuntu0.18.04.1"`: versión que se anuncia, típica de Ubuntu 18.04.

### `_packet(seq, payload: bytes) -> bytes`

Todo mensaje MySQL va dentro de un **paquete** con este formato:

```
[ 3 bytes: longitud del payload ][ 1 byte: número de secuencia ][ payload ]
```

`struct.pack("<I", len(payload))[:3]` convierte la longitud en 4 bytes *little-endian* y se queda con
los 3 primeros. El número de secuencia aumenta en cada mensaje de la conversación.

### `_handshake() -> bytes`

Construye el **saludo inicial** que el servidor MySQL envía apenas alguien se conecta (protocolo 10):

| Campo | Valor | Explicación |
|---|---|---|
| Versión de protocolo | `0x0a` (10) | La versión que usan todos los MySQL modernos |
| Versión del servidor | `5.7.33-0ubuntu...` + byte 0 | Lo que lee `nmap -sV` |
| Thread ID | `1337` | Identificador de conexión (cualquier número sirve) |
| Salt (parte 1) | 8 bytes aleatorios | Semilla para cifrar la contraseña |
| Capacidades | `0xF7FF` y `0x81FF` | Funciones que el servidor dice soportar (protocolo 4.1, conexión segura, etc.) |
| Charset | `0x21` | utf8 |
| Estado | `0x0002` | autocommit activado |
| Salt (parte 2) | 12 bytes aleatorios | Resto de la semilla |
| Plugin de autenticación | `mysql_native_password` | Método de contraseña clásico de MySQL |

El salt se genera con `os.urandom(20)` y se reemplazan los bytes `0x00` por `0x01`, porque el `0x00`
marca el fin de una cadena en este protocolo.

### `_access_denied(seq, user, ip) -> bytes`

Construye el paquete de error que MySQL envía cuando el login falla:

```
0xFF  +  código 1045  +  "#28000"  +  "Access denied for user 'root'@'IP' (using password: YES)"
```

`0xFF` indica "paquete de error", `1045` es el código real de "acceso denegado" y `28000` es el
estado SQL estándar.

### Clase `MySQLTrap(BaseTrap)`

`service = "MySQL"`

#### `interact(self, conn, addr, result)`

1. Envía el handshake.
2. Recibe la respuesta del cliente (`HandshakeResponse41`). Si es muy corta, termina.
3. Lee el **número de secuencia** (byte 3) y el cuerpo (desde el byte 4).
4. El cuerpo tiene esta estructura:
   ```
   capacidades(4) + tamaño máx. paquete(4) + charset(1) + relleno(23) = 32 bytes
   usuario terminado en 0x00
   longitud del hash(1) + hash de la contraseña
   ...
   ```
   Por eso el usuario empieza en la posición 32 y termina en el siguiente byte `0x00`.
5. Lee el **hash** de la contraseña y guarda sus primeros 16 caracteres hexadecimales, por ejemplo
   `[hash 3f2a9c...]`. Si viene vacío, guarda `(vacia)`.
6. Responde con `_access_denied()` usando el siguiente número de secuencia.

**¿Por qué solo el hash?** MySQL nunca envía la contraseña en texto plano: el cliente la combina con el
salt usando SHA1 (`SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))`). Es imposible recuperar la
contraseña original directamente, a diferencia de FTP.

---

## 8. `honeypot/logger.py`: base de datos y geolocalización

### Variables globales

| Variable | Para qué |
|---|---|
| `BASE_DIR` | Carpeta raíz del proyecto |
| `DB_PATH` | Ruta del archivo `data/honeywatch.db` |
| `_db_lock` | `threading.Lock` que evita que dos hilos escriban en SQLite al mismo tiempo |
| `_geo_queue` | Cola (`queue.Queue`) de IPs pendientes de geolocalizar |
| `_geo_cache` | Diccionario `ip → datos de ubicación`, para no consultar dos veces la misma IP |
| `_geo_worker_started` | Evita arrancar dos veces el hilo de geolocalización |
| `SCHEMA` | SQL que crea la tabla `attempts` y sus índices |
| `MAX_PAYLOAD = 4000` | Máximo de caracteres guardados por intento |
| `BRUTE_THRESHOLD = 5` | Intentos necesarios para considerar fuerza bruta |
| `BRUTE_WINDOW_MIN = 1` | Ventana de tiempo, en minutos, para contar esos intentos |
| `ALERT_COOLDOWN_S = 300` | Segundos mínimos entre dos alertas de la misma IP |
| `_last_alert` | Diccionario `ip → momento de la última alerta` |

### Tabla `attempts`

| Columna | Tipo | Contenido |
|---|---|---|
| `id` | INTEGER, autoincremental | Identificador |
| `timestamp` | TEXT | `AAAA-MM-DD HH:MM:SS` |
| `ip` | TEXT | IP del atacante |
| `src_port` | INTEGER | Puerto de origen |
| `dst_port` | INTEGER | Puerto atacado |
| `service` | TEXT | `SSH`, `FTP`, `HTTP`, `WordPress` o `MySQL` |
| `payload` | TEXT | Lo que envió el atacante |
| `username` / `password` | TEXT | Credenciales capturadas |
| `country`, `country_code`, `city`, `lat`, `lon`, `isp` | TEXT / REAL | Geolocalización (se llenan después) |

Índices: `idx_attempts_ts` sobre `timestamp` e `idx_attempts_ip` sobre `ip`. Aceleran las consultas
del dashboard ("últimos 30 minutos", "intentos por IP").

### `_connect()`

Abre una conexión a SQLite con `timeout=10` (espera hasta 10 s si la base está bloqueada) y
`row_factory = sqlite3.Row`, que permite leer las columnas por nombre (`row["ip"]`) y convertirlas a
diccionario.

Se abre una conexión nueva en cada operación porque las conexiones de SQLite **no se deben compartir
entre hilos**.

### 1) Crear la base de datos

#### `init_db()`

Crea la carpeta `data/` si no existe, ejecuta `SCHEMA` (que usa `CREATE TABLE IF NOT EXISTS`, así que
no borra nada si ya existe) y arranca el hilo de geolocalización.

### 2) Registrar un intento

#### `log_attempt(ip, dst_port, service, payload="", src_port=None, username=None, password=None) -> int`

1. Genera la fecha y hora actual.
2. Recorta el payload a `MAX_PAYLOAD` caracteres.
3. Hace el `INSERT` **protegido con `_db_lock`**.
4. Mete la IP en `_geo_queue` para que el hilo de geolocalización la procese **después**. Así una
   consulta lenta a internet nunca frena a las trampas.
5. Llama a `_check_bruteforce()`.
6. Devuelve el `id` del nuevo registro.

Las columnas de ubicación quedan en `NULL`. Por eso el dashboard muestra "buscando…" durante uno o dos
segundos.

#### `_check_bruteforce(ip, service)`

1. Cuenta los intentos de esa IP en el último minuto.
2. Si son **5 o más** y la última alerta de esa IP fue hace más de **5 minutos**:
   - Imprime `[!] ALERTA: posible fuerza bruta desde ...` en consola.
   - Envía una alerta a Telegram con `alerts.notify()`.

El "enfriamiento" de 5 minutos evita llenar el celular con cientos de mensajes durante un ataque.

### 3) Consultas para el dashboard

#### `get_recent(n=50) -> list[dict]`

Devuelve los últimos `n` intentos, del más reciente al más antiguo, como lista de diccionarios.

#### `get_stats(minutes=30) -> dict`

Calcula todas las estadísticas del dashboard en una sola llamada:

| Clave | Consulta |
|---|---|
| `total` | Número total de intentos |
| `unique_ips` | Número de IPs distintas |
| `last_minute` | Intentos en los últimos 60 segundos |
| `by_service` | Intentos por servicio, de mayor a menor |
| `by_country` | Top 8 países (los que aún no tienen ubicación salen como "Pendiente") |
| `top_ips` | Top 8 IPs con su país y su ciudad |
| `top_creds` | Top 8 combinaciones usuario/contraseña/servicio más probadas |
| `timeline` | Intentos por minuto en los últimos `minutes` minutos |

Para la línea de tiempo agrupa por los primeros 16 caracteres del timestamp (`AAAA-MM-DD HH:MM`) y
después **rellena con 0** los minutos sin actividad. Sin ese relleno, la gráfica saltaría de un punto a
otro y no se vería continua.

#### `clear_db()`

Borra todas las filas de `attempts`. Se usa con `python main.py --clear` antes de una demo.

### Geolocalización

#### `_is_private(ip) -> bool`

Devuelve `True` para IPs privadas (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`), de loopback
(`127.x.x.x`) o link-local (`169.254.x.x`). Esas IPs no existen en internet, así que no tiene sentido
geolocalizarlas. Si el texto no es una IP válida, también devuelve `True`, por seguridad.

#### `geolocate(ip) -> dict`

1. Si la IP está en `_geo_cache`, devuelve el valor guardado.
2. Si es privada, devuelve `{"country": "Red local", "country_code": "LAN", ...}`.
3. Si es pública, consulta `http://ip-api.com/json/<ip>` pidiendo solo los campos necesarios.
4. Si la respuesta es `success`, arma el diccionario con país, código, ciudad, latitud, longitud e ISP.
5. **Si no hay internet**, devuelve "Desconocido" **sin guardarlo en caché**, para poder reintentarlo
   la próxima vez que esa IP ataque.

#### `_geo_worker()`

Hilo que corre para siempre:

1. Espera una IP en la cola (`_geo_queue.get()` bloquea hasta que llegue una).
2. La geolocaliza.
3. Actualiza **todas** las filas de esa IP que todavía no tienen país (`WHERE ip=? AND country IS NULL`).
4. Si la IP era pública, espera 1,5 segundos. El plan gratuito de ip-api.com permite 45 consultas por
   minuto, y 1,5 s entre consultas da 40 por minuto, por debajo del límite.

#### `_start_geo_worker()`

Arranca `_geo_worker` en un hilo `daemon` llamado `geo-worker`, solo la primera vez que se llama.

---

## 9. `honeypot/alerts.py`: alertas por Telegram

Envía mensajes al celular a través de un bot de Telegram. Es **opcional**: si no está configurado,
todo lo demás funciona igual.

### Configuración

```powershell
$env:HW_TELEGRAM_TOKEN = "token que te da @BotFather"
$env:HW_TELEGRAM_CHAT  = "tu chat_id"
```

### `_get_setting(name) -> str`

Lee una variable de entorno. Si no existe y el sistema es Windows, la busca en el **registro de
Windows** (`HKEY_CURRENT_USER\Environment`).

Esto resuelve un problema común: si guardas la variable con `setx`, las terminales que ya estaban
abiertas no la ven. Leyendo el registro, HoneyWatch la encuentra igual.

### Variables `TOKEN` y `CHAT_ID`

Se leen una sola vez, al importar el módulo.

### `is_configured() -> bool`

`True` si existen el token y el chat_id.

### `_send(text) -> bool`

Hace un `POST` a `https://api.telegram.org/bot<TOKEN>/sendMessage` con el JSON
`{"chat_id": ..., "text": ...}`. Devuelve `True` si Telegram respondió `"ok": true`. Si algo falla
(sin internet, token malo), imprime el error y devuelve `False`, sin detener el programa.

### `notify(text)`

Si las alertas están configuradas, llama a `_send()` **en un hilo aparte**. Así, si Telegram tarda en
responder, la trampa que detectó el ataque no se queda esperando.

### `find_chat_id()`

Ayuda a configurar el bot. Consulta `getUpdates` (los últimos mensajes que recibió el bot) y muestra
los `chat_id` encontrados. Si el bot no tiene mensajes, explica qué hacer: abrir el bot en Telegram,
pulsar "Iniciar" y escribirle algo.

### Uso desde la consola

```
python -m honeypot.alerts            # envía un mensaje de prueba
python -m honeypot.alerts --chat-id  # muestra tu chat_id
```

---

## 10. `dashboard/app.py`: API web con Flask

### `create_app(trap_status=None) -> Flask`

Fábrica que crea y configura la aplicación Flask (patrón *application factory*).

`trap_status` es la lista `[{service, port, active}, ...]` que arma `main.py`. Se guarda en
`app.config["TRAP_STATUS"]` para que la API la devuelva.

Al inicio del archivo, `sys.path.insert(...)` agrega la carpeta raíz del proyecto a la ruta de
importación, para poder hacer `from honeypot import logger` aunque se ejecute `app.py` directamente.

### Rutas

| Ruta | Función | Devuelve |
|---|---|---|
| `GET /` | `index()` | La página `templates/index.html` |
| `GET /api/attempts?limit=N` | `attempts()` | JSON con los últimos N intentos (por defecto 50, **máximo 500** para no sobrecargar el servidor) |
| `GET /api/stats` | `stats()` | JSON con `logger.get_stats()` más la lista `traps` |

### Ejecución independiente

```
python dashboard/app.py
```

Abre **solo** el dashboard, sin trampas, en `127.0.0.1:5000`. Sirve para revisar los datos guardados
sin abrir los puertos.

---

## 11. `dashboard/templates/index.html`: interfaz del dashboard

Página única con HTML, CSS (`static/style.css`) y JavaScript. Usa **Chart.js 4.4.1** para las gráficas.

### Secciones de la página

| Sección | Contenido |
|---|---|
| Encabezado | Logo e indicador **EN VIVO** / **SIN CONEXIÓN** |
| `#traps` | Un indicador por servicio con su puerto y estado |
| KPIs | Intentos totales, IPs únicas, último minuto y servicio más atacado |
| Gráficas | Actividad de los últimos 30 minutos (línea), ataques por servicio (dona) y origen por país (barras) |
| Tablas | Top IPs atacantes y credenciales capturadas |
| Feed | Últimos 60 intentos. Al hacer clic en una fila se abre una ventana con el payload completo |

### Constantes y variables de JavaScript

| Nombre | Para qué |
|---|---|
| `COLORS` | Color de cada servicio: SSH rojo, FTP naranja, HTTP azul, WordPress morado, MySQL verde |
| `REFRESH_MS = 2000` | Cada cuántos milisegundos se actualizan los datos |
| `seenIds` | IDs de intentos ya mostrados, para resaltar los nuevos |
| `firstLoad` | En la primera carga no se resalta nada |
| `attemptsById` | Intentos indexados por id, para abrir el detalle al hacer clic |

### Funciones de JavaScript

#### `esc(s)`

Escapa `& < > " '`. **Todo** lo que viene del atacante (usuario, payload, IP...) pasa por esta función
antes de insertarse en la página. Sin ella, un atacante podría escribir `<script>` como usuario y
ejecutar código **en el navegador de quien mira el dashboard** (XSS almacenado).

#### `locHtml(a)`

Devuelve el HTML de la columna "Ubicación":
- Sin país todavía → `buscando…`
- IP privada → etiqueta `Red local`
- IP pública → código de país y ciudad

#### `refresh()` (asíncrona)

Pide `/api/stats` y `/api/attempts?limit=60` **en paralelo** (`Promise.all`), y llama a `renderStats()`
y `renderFeed()`. Si falla (por ejemplo, porque se cerró HoneyWatch), cambia el indicador a
**SIN CONEXIÓN**.

#### `renderStats(s)`

Actualiza los KPIs, los indicadores de las trampas, las tres gráficas (cambiando sus datos y llamando a
`chart.update()`) y las tablas de top IPs y credenciales.

#### `renderFeed(list)`

Redibuja la tabla de intentos recientes. Las filas que no estaban en `seenIds` llevan la clase `new`,
que las resalta con una animación. Si no hay intentos, muestra "Esperando el primer ataque…".

#### Ventana de detalle (modal)

- Clic en una fila del feed → muestra servicio, IP, puertos, fecha, credenciales y payload completo.
  Usa `textContent` en vez de `innerHTML`, que **nunca** interpreta HTML, así que es seguro.
- Se cierra con el botón ✕ o haciendo clic fuera de la ventana.

---

## 12. `tools/simular_ataque.py`: atacante de prueba

Script para la demo: actúa como un bot de fuerza bruta contra las trampas, usando sockets directamente.

### Constante `CREDS`

Lista de 9 combinaciones usuario/contraseña de las más usadas por bots reales: `root/root`,
`admin/admin`, `admin/123456`, `root/toor`, `pi/raspberry` (Raspberry Pi), `oracle/oracle`,
`postgres/postgres`, etc.

### Funciones de ataque

Todas reciben `host` y `port`.

| Función | Qué simula |
|---|---|
| `ssh()` | Se conecta, lee el banner del servidor y envía el banner de un bot (`SSH-2.0-libssh2_1.10.0`) más bytes aleatorios que imitan el inicio del intercambio de claves |
| `ftp()` | Saludo → `USER` → `PASS` con credenciales aleatorias de `CREDS` → `QUIT` |
| `http()` | Un `GET /admin` identificándose como `sqlmap` (herramienta de inyección SQL) y un `POST /login` con credenciales |
| `wordpress()` | 1) `POST /wp-login.php` identificándose como **WPScan**. 2) `POST /xmlrpc.php` con `system.multicall`, que prueba **las 9 contraseñas de `CREDS` en una sola petición** |
| `mysql()` | Lee el handshake, muestra la versión del servidor y envía un `HandshakeResponse41` construido a mano con un usuario y un hash aleatorio |
| `scan()` | Abre y cierra la conexión sin enviar nada, como un escaneo de puertos |

### `main()`

| Argumento | Por defecto | Significado |
|---|---|---|
| `host` | `127.0.0.1` | IP del honeypot |
| `--alt-ports` | apagado | Ataca los puertos alternos |
| `--rondas` | `3` | Cuántas veces repetir el ataque completo |

En cada ronda ataca los 5 servicios en orden. Con un 50 % de probabilidad agrega además un `scan()`,
para que en el dashboard también aparezcan escaneos. Espera 0,3 s entre servicios.

---

## 13. Concurrencia: cómo conviven los hilos

Con HoneyWatch corriendo hay varios hilos trabajando a la vez:

| Hilo | Cantidad | Qué hace |
|---|---|---|
| Principal | 1 | Ejecuta Flask (el dashboard) |
| `SSH-trap`, `FTP-trap`, `HTTP-trap`, `MySQL-trap` | 4 | Cada uno espera conexiones en su puerto (`accept`) |
| Por conexión | 1 por atacante | Ejecuta `_handle()` y muere al terminar |
| `geo-worker` | 1 | Geolocaliza IPs de la cola |
| Envío a Telegram | 1 por alerta | Envía el mensaje y muere |
| Flask | 1 por petición | `threaded=True` atiende las peticiones del dashboard en paralelo |

**Protecciones:**
- `_db_lock` serializa las **escrituras** en SQLite. SQLite admite un solo escritor a la vez.
- Cada operación abre su **propia** conexión a SQLite. Las conexiones no se comparten entre hilos.
- Todas las tareas lentas (geolocalización, Telegram) van en **hilos aparte o en cola**, para que las
  trampas respondan siempre rápido.
- Todos los hilos son `daemon`: al presionar `Ctrl+C` se cierran solos.

---

## 14. Seguridad del propio honeypot

Un honeypot recibe datos de atacantes, así que tiene que protegerse a sí mismo:

| Riesgo | Protección | Dónde |
|---|---|---|
| Que el atacante obtenga acceso real | Los servicios son falsos: nunca ejecutan comandos ni leen archivos, siempre responden "acceso denegado" | Todas las trampas |
| Agotar la memoria con datos gigantes | Límites: 16 KB por petición HTTP, 4 KB en SSH y MySQL, 1 KB por línea FTP, 20 comandos FTP, 4000 caracteres guardados | Trampas y `logger.py` |
| Conexiones colgadas para siempre | `timeout` de 15 s por conexión | `BaseTrap` |
| Inyección SQL | Todas las consultas usan parámetros `?`, nunca se concatena texto del atacante | `logger.py` |
| XSS en el dashboard | `esc()` y `textContent` para todo dato del atacante | `index.html` |
| XSS en las páginas falsas | `_esc()` antes de insertar el usuario en el HTML | `http_trap.py` |
| Bombas XML | Expresiones regulares en vez de parser XML | `http_trap.py` (`_xmlrpc`) |
| Falsificar la IP con `CF-Connecting-IP` | Solo se acepta si la conexión viene de `127.0.0.1` | `http_trap.py` |
| Que otros vean el dashboard | Por defecto solo escucha en `127.0.0.1` | `main.py` |
| Subir datos capturados a GitHub | `data/*.db` está en `.gitignore` | `.gitignore` |

---

## 15. Cómo agregar una trampa nueva

Ejemplo: un Telnet falso en el puerto 23.

**1. Crear `honeypot/telnet_trap.py`:**

```python
from honeypot.base_trap import BaseTrap, recv_line, to_text


class TelnetTrap(BaseTrap):
    service = "Telnet"

    def interact(self, conn, addr, result):
        log = []
        try:
            conn.sendall(b"Ubuntu 20.04 LTS\r\nlogin: ")
            user = to_text(recv_line(conn)).strip()
            result["username"] = user
            log.append(user)

            conn.sendall(b"Password: ")
            pwd = to_text(recv_line(conn)).strip()
            result["password"] = pwd
            log.append(pwd)

            conn.sendall(b"\r\nLogin incorrect\r\n")
        finally:
            result["payload"] = "\n".join(log)
```

**2. Registrarla en `main.py`:**

```python
from honeypot.telnet_trap import TelnetTrap

TRAPS = [
    ...
    (TelnetTrap, 23, 2323),
]
```

**3. Darle un color en `dashboard/templates/index.html`:**

```javascript
const COLORS = { ..., Telnet: "#ff8fd8" };
```

No hace falta tocar nada más: el registro en la base de datos, la geolocalización, las alertas y el
dashboard funcionan automáticamente gracias a `BaseTrap`.
