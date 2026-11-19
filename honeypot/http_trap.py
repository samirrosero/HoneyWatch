"""
HoneyWatch - http_trap.py
HTTP falso con DOS trampas en el mismo puerto, como un servidor Apache real
donde conviven varias aplicaciones:

1) WordPress  (/wp-login.php, /wp-admin, /xmlrpc.php, /wordpress...)
   WordPress es el CMS mas usado del mundo (~40% de las webs) y por eso el mas
   atacado. Los bots prueban usuarios como "admin" en wp-login.php, y tambien
   usan xmlrpc.php para probar CIENTOS de contrasenas en una sola peticion
   (metodo system.multicall).

2) phpMyAdmin  (cualquier otra ruta: /, /phpmyadmin, /pma, /admin...)
   Herramienta de administracion de bases de datos MySQL. Muy buscada por los
   bots porque muchos servidores la dejan con credenciales por defecto.

Ambas capturan el usuario y la contrasena y siempre responden "acceso denegado".
Tambien se registra la ruta pedida (revela que rutas rastrean los bots).
"""

import html
import ipaddress
import re
from urllib.parse import parse_qs, quote, urlsplit

from honeypot.base_trap import BaseTrap, to_text

SERVER_HEADER = "Apache/2.4.41 (Ubuntu)"
POWERED_BY = "PHP/7.4.3"

# ----------------------------------------------------------------------------
# Pagina de login de phpMyAdmin 5.2 (recreada con CSS, sin imagenes)
# ----------------------------------------------------------------------------
PMA_PAGE = """<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>phpMyAdmin</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{font-family:"Segoe UI",Tahoma,sans-serif;background:#f0f2f5;margin:0;color:#262626}
#page{max-width:400px;margin:40px auto;background:#fff;border:1px solid #ddd;border-radius:4px;overflow:hidden}
#header{background:#6c78af;color:#fff;text-align:center;padding:18px}
#header .logo{font-size:26px;font-weight:bold;letter-spacing:.5px}
#header .logo span{color:#f90}
#header .sub{font-size:12px;opacity:.9;margin-top:4px}
#body{padding:24px 28px 30px}
.welcome{font-size:15px;color:#555;margin:0 0 18px;text-align:center}
label{display:block;font-size:13px;margin:12px 0 4px;color:#444}
input[type=text],input[type=password],select{width:100%;padding:9px;border:1px solid #bbb;border-radius:3px;box-sizing:border-box;font-size:14px}
button{width:100%;margin-top:22px;padding:11px;background:#6c78af;color:#fff;border:0;border-radius:3px;font-size:15px;cursor:pointer}
button:hover{background:#59648f}
.error{background:#f2dede;border:1px solid #ebccd1;color:#a94442;padding:10px 12px;border-radius:3px;font-size:13px;margin-bottom:16px}
#footer{text-align:center;font-size:11px;color:#999;padding:14px}
</style></head>
<body><div id="page">
<div id="header"><div class="logo">php<span>My</span>Admin</div><div class="sub">Bienvenido a phpMyAdmin</div></div>
<div id="body">
{error}
<form method="post" action="index.php?route=/">
<p class="welcome">Iniciar sesion</p>
<label>Idioma - Language</label>
<select><option>Espanol - Spanish</option><option>English</option></select>
<label>Usuario:</label><input type="text" name="pma_username" autofocus>
<label>Contrasena:</label><input type="password" name="pma_password">
<input type="hidden" name="server" value="1">
<button type="submit">Continuar</button>
</form></div>
<div id="footer">phpMyAdmin 5.2.1 &mdash; Apache/2.4.41 (Ubuntu)</div>
</div></body></html>"""

# ----------------------------------------------------------------------------
# Pagina de login de WordPress 6.x (recreada con CSS, sin imagenes)
# ----------------------------------------------------------------------------
WP_PAGE = """<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acceder &lsaquo; Mi blog &#8212; WordPress</title>
<meta name="robots" content="noindex, nofollow">
<style>
body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;font-size:13px;color:#3c434a;margin:0}
#login{width:320px;padding:5% 0 0;margin:auto}
#login h1{text-align:center;margin:0 0 25px}
#login h1 a{display:inline-block;width:84px;height:84px;border-radius:50%;background:#3c434a;color:#f0f0f1;
  font:400 58px/84px Georgia,"Times New Roman",serif;text-decoration:none}
.login form{background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04);padding:26px 24px;margin-top:20px}
.login label{font-size:14px;line-height:1.5;display:inline-block;margin-bottom:3px}
.login input[type=text],.login input[type=password]{width:100%;box-sizing:border-box;font-size:24px;line-height:1.33;
  padding:0 8px;min-height:40px;margin:0 6px 16px 0;border:1px solid #8c8f94;border-radius:4px;background:#fff}
.forgetmenot{float:left;margin-top:6px}
.submit{text-align:right}
.button-primary{background:#2271b1;border:1px solid #2271b1;color:#fff;border-radius:3px;padding:0 12px;min-height:32px;
  font-size:13px;cursor:pointer}
.button-primary:hover{background:#135e96}
#login_error{border-left:4px solid #d63638;background:#fff;padding:12px;margin-top:20px;box-shadow:0 1px 1px rgba(0,0,0,.04)}
#login_error a{color:#2271b1}
#nav,#backtoblog{padding:0 24px;margin:24px 0 0;font-size:13px}
#nav a,#backtoblog a{color:#50575e;text-decoration:none}
.language-switcher{text-align:center;margin-top:24px;color:#50575e}
</style></head>
<body class="login js login-action-login wp-core-ui locale-es-es">
<div id="login">
<h1><a href="/" title="Funciona con WordPress">W</a></h1>
{error}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Nombre de usuario o correo electr&oacute;nico</label>
<input type="text" name="log" id="user_login" value="{user}" size="20" autocapitalize="off" autocomplete="username"></p>
<div class="user-pass-wrap"><label for="user_pass">Contrase&ntilde;a</label>
<input type="password" name="pwd" id="user_pass" value="" size="20" autocomplete="current-password"></div>
<p class="forgetmenot"><input name="rememberme" type="checkbox" id="rememberme" value="forever">
<label for="rememberme">Recu&eacute;rdame</label></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Acceder">
<input type="hidden" name="redirect_to" value="/wp-admin/">
<input type="hidden" name="testcookie" value="1"></p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">&iquest;Has olvidado tu contrase&ntilde;a?</a></p>
<p id="backtoblog"><a href="/">&larr; Ir a Mi blog</a></p>
</div>
<div class="language-switcher">Espa&ntilde;ol</div>
</body></html>"""

XMLRPC_FAULT = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member><name>faultCode</name><value><int>403</int></value></member>
        <member><name>faultString</name><value><string>Nombre de usuario o contrase&#241;a incorrectos.</string></value></member>
      </struct>
    </value>
  </fault>
</methodResponse>
"""

# Rutas que se consideran WordPress
WP_PATTERN = re.compile(r"(wp-login\.php|/wp-admin|xmlrpc\.php|^/wordpress|^/wp/|/wp-content|/wp-includes)",
                        re.IGNORECASE)
# Nombres de metodo XML-RPC (para separarlos de usuarios/contrasenas)
XMLRPC_METHOD = re.compile(r"^(wp|system|metaWeblog|blogger|mt|pingback|demo)\.\w+$")


class HTTPTrap(BaseTrap):
    service = "HTTP"

    def interact(self, conn, addr, result):
        raw = b""
        summary = ""
        try:
            # Leer cabeceras
            while b"\r\n\r\n" not in raw and len(raw) < 16384:
                chunk = conn.recv(2048)
                if not chunk:
                    break
                raw += chunk

            head, _, body = raw.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            request_line = lines[0] if lines else ""
            headers = {}
            for line in lines[1:]:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

            # Leer el cuerpo completo si es un POST
            try:
                length = min(int(headers.get("content-length", "0") or 0), 16384)
            except ValueError:
                length = 0
            while len(body) < length:
                chunk = conn.recv(2048)
                if not chunk:
                    break
                body += chunk
            raw = head + b"\r\n\r\n" + body

            if not request_line:
                return

            # Si la conexion viene del tunel de Cloudflare (cloudflared corre en esta
            # misma PC, por eso llega desde 127.0.0.1), la IP real del visitante viene
            # en la cabecera CF-Connecting-IP. Solo se confia en ella si la conexion es
            # local: alguien desde afuera no puede falsificar su IP con esta cabecera.
            real_ip = headers.get("cf-connecting-ip", "")
            if real_ip and _is_loopback(addr[0]) and _valid_ip(real_ip):
                result["ip"] = real_ip

            parts = request_line.split(" ")
            method = parts[0].upper()
            path = urlsplit(parts[1]).path if len(parts) > 1 else "/"

            if WP_PATTERN.search(path):
                result["service"] = "WordPress"
                summary = self._wordpress(conn, method, path, body, result)
            else:
                self._phpmyadmin(conn, method, body, result)
        finally:
            result["payload"] = summary + to_text(raw)

    # ------------------------------------------------------------------
    # phpMyAdmin
    # ------------------------------------------------------------------
    def _phpmyadmin(self, conn, method, body, result):
        error = ""
        if method == "POST" and body:
            form = parse_qs(body.decode("latin-1"))
            user = _first(form, "pma_username", "username", "user")
            pwd = _first(form, "pma_password", "password", "pass")
            if user is not None or pwd is not None:
                result["username"] = user
                result["password"] = pwd
            # Mensaje de error identico al que muestra phpMyAdmin
            error = ('<div class="error">#1045 - Acceso denegado para el usuario '
                     f"'{_esc(user)}'@'localhost' (using password: "
                     f"{'YES' if pwd else 'NO'})</div>")
        _send(conn, "200 OK", PMA_PAGE.replace("{error}", error))

    # ------------------------------------------------------------------
    # WordPress
    # ------------------------------------------------------------------
    def _wordpress(self, conn, method, path, body, result):
        low = path.lower()

        # /wp-admin redirige al login, igual que WordPress real
        if "/wp-admin" in low:
            target = "/wp-login.php?redirect_to=" + quote("http://localhost" + path, safe="") + "&reauth=1"
            _send(conn, "302 Found", "", extra={"Location": target})
            return ""

        # xmlrpc.php: el metodo favorito para fuerza bruta masiva
        if "xmlrpc.php" in low:
            if method != "POST":
                _send(conn, "405 Method Not Allowed",
                      "XML-RPC server accepts POST requests only.", ctype="text/plain")
                return ""
            return self._xmlrpc(conn, body, result)

        # wp-login.php (y cualquier otra ruta de WordPress)
        error, user = "", ""
        if method == "POST" and body:
            form = parse_qs(body.decode("latin-1"))
            user = _first(form, "log", "username", "user")
            pwd = _first(form, "pwd", "password", "pass")
            if user is not None or pwd is not None:
                result["username"] = user
                result["password"] = pwd
            # Mensaje identico al de WordPress en espanol
            error = ('<div id="login_error"><strong>Error:</strong> la contrase&ntilde;a que has '
                     f'introducido para el nombre de usuario <strong>{_esc(user)}</strong> no es correcta. '
                     '<a href="/wp-login.php?action=lostpassword">&iquest;Has olvidado tu contrase&ntilde;a?</a></div>')
        page = WP_PAGE.replace("{error}", error).replace("{user}", _esc(user))
        _send(conn, "200 OK", page,
              extra={"Set-Cookie": "wordpress_test_cookie=WP%20Cookie%20check; path=/; HttpOnly"})
        return ""

    def _xmlrpc(self, conn, body, result):
        """Extrae usuario/contrasena de wp.getUsersBlogs o system.multicall."""
        xml = body.decode("utf-8", "replace")
        m = re.search(r"<methodName>\s*([^<]+?)\s*</methodName>", xml)
        method_name = m.group(1) if m else "?"

        # Valores "hoja" del XML (los que no contienen otras etiquetas)
        values = [html.unescape(v) for v in
                  re.findall(r"<value>\s*(?:<string>)?([^<]*)(?:</string>)?\s*</value>", xml)]
        values = [v for v in values if not XMLRPC_METHOD.match(v)]

        pairs = list(zip(values[0::2], values[1::2]))
        if pairs:
            result["username"], result["password"] = pairs[0]

        _send(conn, "200 OK", XMLRPC_FAULT, ctype="text/xml; charset=UTF-8")

        summary = f"[XML-RPC] metodo: {method_name}\n"
        if len(pairs) > 1:
            summary += f"[XML-RPC] {len(pairs)} contrasenas probadas en UNA sola peticion:\n"
            summary += "".join(f"   {u} / {p}\n" for u, p in pairs[:30])
            if len(pairs) > 30:
                summary += f"   ... y {len(pairs) - 30} mas\n"
        return summary + "\n"


# ----------------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------------
def _send(conn, status, content, ctype="text/html; charset=UTF-8", extra=None):
    body = content.encode()
    head = (f"HTTP/1.1 {status}\r\n"
            f"Server: {SERVER_HEADER}\r\n"
            f"X-Powered-By: {POWERED_BY}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n")
    for k, v in (extra or {}).items():
        head += f"{k}: {v}\r\n"
    head += "Connection: close\r\n\r\n"
    conn.sendall(head.encode() + body)


def _valid_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def _first(form, *names):
    """Devuelve el primer campo del formulario que exista."""
    for n in names:
        if n in form:
            return form[n][0]
    return None


def _esc(text):
    """Escapa el texto del atacante antes de meterlo en el HTML (evita inyeccion)."""
    if text is None:
        return ""
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))
