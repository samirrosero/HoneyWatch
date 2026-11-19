"""
HoneyWatch - logger.py
Base de datos SQLite donde todos los traps registran los intentos de conexion.
Tambien geolocaliza las IPs en segundo plano usando ip-api.com (gratis, sin registro).
"""

import ipaddress
import json
import os
import queue
import sqlite3
import threading
import time
import urllib.request
from datetime import datetime, timedelta

from honeypot import alerts

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "honeywatch.db")

_db_lock = threading.Lock()          # SQLite + varios hilos: serializamos las escrituras
_geo_queue = queue.Queue()            # IPs pendientes de geolocalizar
_geo_cache = {}                       # ip -> dict con datos de ubicacion
_geo_worker_started = False

SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    ip           TEXT    NOT NULL,
    src_port     INTEGER,
    dst_port     INTEGER NOT NULL,
    service      TEXT    NOT NULL,
    payload      TEXT,
    username     TEXT,
    password     TEXT,
    country      TEXT,
    country_code TEXT,
    city         TEXT,
    lat          REAL,
    lon          REAL,
    isp          TEXT
);
CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_attempts_ip ON attempts(ip);
"""

MAX_PAYLOAD = 4000  # caracteres maximos guardados por intento

# Deteccion de fuerza bruta: aviso cuando una IP hace muchos intentos seguidos
BRUTE_THRESHOLD = 5        # intentos...
BRUTE_WINDOW_MIN = 1       # ...en este numero de minutos
ALERT_COOLDOWN_S = 300     # maximo un aviso cada 5 minutos por IP
_last_alert = {}           # ip -> momento del ultimo aviso


def _connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# ----------------------------------------------------------------------------
# 1) Crear la base de datos
# ----------------------------------------------------------------------------
def init_db():
    """Crea la carpeta data/ y la tabla de intentos si no existen."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with _db_lock, _connect() as conn:
        conn.executescript(SCHEMA)
    _start_geo_worker()


# ----------------------------------------------------------------------------
# 2) Registrar un intento
# ----------------------------------------------------------------------------
def log_attempt(ip, dst_port, service, payload="", src_port=None,
                username=None, password=None):
    """Guarda un intento de conexion y encola la IP para geolocalizarla."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    payload = (payload or "")[:MAX_PAYLOAD]

    with _db_lock, _connect() as conn:
        cur = conn.execute(
            """INSERT INTO attempts
               (timestamp, ip, src_port, dst_port, service, payload, username, password)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, ip, src_port, dst_port, service, payload, username, password),
        )
        attempt_id = cur.lastrowid

    _geo_queue.put(ip)
    _check_bruteforce(ip, service)
    return attempt_id


def _check_bruteforce(ip, service):
    """Si una IP supera el umbral de intentos, manda una alerta al celular."""
    since = (datetime.now() - timedelta(minutes=BRUTE_WINDOW_MIN)).strftime("%Y-%m-%d %H:%M:%S")
    with _connect() as conn:
        n = conn.execute("SELECT COUNT(*) FROM attempts WHERE ip=? AND timestamp>=?",
                         (ip, since)).fetchone()[0]

    if n >= BRUTE_THRESHOLD and time.time() - _last_alert.get(ip, 0) > ALERT_COOLDOWN_S:
        _last_alert[ip] = time.time()
        print(f"[!] ALERTA: posible fuerza bruta desde {ip} ({n} intentos en {BRUTE_WINDOW_MIN} min)")
        alerts.notify(
            f"🚨 HoneyWatch: posible fuerza bruta\n"
            f"IP: {ip}\n"
            f"Intentos: {n} en el ultimo minuto\n"
            f"Ultimo servicio: {service}\n"
            f"Hora: {datetime.now():%H:%M:%S}"
        )


# ----------------------------------------------------------------------------
# 3) Consultas para el dashboard
# ----------------------------------------------------------------------------
def get_recent(n=50):
    """Devuelve los ultimos N intentos (el mas reciente primero)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM attempts ORDER BY id DESC LIMIT ?", (n,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats(minutes=30):
    """Agregados para las graficas del dashboard."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT ip) FROM attempts").fetchone()[0]

        by_service = conn.execute(
            "SELECT service, COUNT(*) AS c FROM attempts GROUP BY service ORDER BY c DESC"
        ).fetchall()

        by_country = conn.execute(
            """SELECT COALESCE(country, 'Pendiente') AS country, COUNT(*) AS c
               FROM attempts GROUP BY country ORDER BY c DESC LIMIT 8"""
        ).fetchall()

        top_ips = conn.execute(
            """SELECT ip, COUNT(*) AS c, MAX(country) AS country, MAX(city) AS city
               FROM attempts GROUP BY ip ORDER BY c DESC LIMIT 8"""
        ).fetchall()

        top_creds = conn.execute(
            """SELECT username, password, service, COUNT(*) AS c FROM attempts
               WHERE username IS NOT NULL
               GROUP BY username, password, service ORDER BY c DESC LIMIT 8"""
        ).fetchall()

        since = (datetime.now() - timedelta(minutes=minutes - 1)).strftime("%Y-%m-%d %H:%M")
        timeline_rows = conn.execute(
            """SELECT substr(timestamp, 1, 16) AS minute, COUNT(*) AS c
               FROM attempts WHERE substr(timestamp, 1, 16) >= ?
               GROUP BY minute""",
            (since,),
        ).fetchall()

        last_minute = conn.execute(
            "SELECT COUNT(*) FROM attempts WHERE timestamp >= ?",
            ((datetime.now() - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"),),
        ).fetchone()[0]

    # Rellenar los minutos sin actividad con 0 para que la grafica sea continua
    counts = {r["minute"]: r["c"] for r in timeline_rows}
    now = datetime.now().replace(second=0, microsecond=0)
    timeline = []
    for i in range(minutes - 1, -1, -1):
        m = now - timedelta(minutes=i)
        key = m.strftime("%Y-%m-%d %H:%M")
        timeline.append({"minute": m.strftime("%H:%M"), "count": counts.get(key, 0)})

    return {
        "total": total,
        "unique_ips": unique_ips,
        "last_minute": last_minute,
        "by_service": [dict(r) for r in by_service],
        "by_country": [dict(r) for r in by_country],
        "top_ips": [dict(r) for r in top_ips],
        "top_creds": [dict(r) for r in top_creds],
        "timeline": timeline,
    }


def clear_db():
    """Borra todos los intentos (util antes de una demo)."""
    with _db_lock, _connect() as conn:
        conn.execute("DELETE FROM attempts")


# ----------------------------------------------------------------------------
# Geolocalizacion (hilo en segundo plano)
# ----------------------------------------------------------------------------
def _is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return True


def geolocate(ip):
    """Consulta ip-api.com. Las IPs privadas/locales no se consultan."""
    if ip in _geo_cache:
        return _geo_cache[ip]

    if _is_private(ip):
        info = {"country": "Red local", "country_code": "LAN", "city": "LAN",
                "lat": None, "lon": None, "isp": "Red privada"}
    else:
        info = {"country": "Desconocido", "country_code": "??", "city": None,
                "lat": None, "lon": None, "isp": None}
        url = (f"http://ip-api.com/json/{ip}"
               "?fields=status,country,countryCode,city,lat,lon,isp")
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                info = {"country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "city": data.get("city"),
                        "lat": data.get("lat"), "lon": data.get("lon"),
                        "isp": data.get("isp")}
        except Exception:
            return info  # sin internet: no lo cacheamos para reintentar luego

    _geo_cache[ip] = info
    return info


def _geo_worker():
    while True:
        ip = _geo_queue.get()
        info = geolocate(ip)
        try:
            with _db_lock, _connect() as conn:
                conn.execute(
                    """UPDATE attempts SET country=?, country_code=?, city=?,
                       lat=?, lon=?, isp=? WHERE ip=? AND country IS NULL""",
                    (info["country"], info["country_code"], info["city"],
                     info["lat"], info["lon"], info["isp"], ip),
                )
        except sqlite3.Error as e:
            print(f"[logger] Error guardando geolocalizacion: {e}")
        # ip-api.com permite 45 consultas/minuto en el plan gratis
        if not _is_private(ip):
            threading.Event().wait(1.5)


def _start_geo_worker():
    global _geo_worker_started
    if not _geo_worker_started:
        threading.Thread(target=_geo_worker, daemon=True, name="geo-worker").start()
        _geo_worker_started = True
