"""
HoneyWatch - main.py
Arranca todos los traps en paralelo (un hilo por servicio) y el dashboard web.

Uso:
    python main.py                 # puertos reales: 22, 21, 80, 3306
    python main.py --alt-ports     # puertos alternos: 2222, 2121, 8888, 3307
    python main.py --clear         # borra los registros antes de empezar
"""

import argparse
import logging

from dashboard.app import create_app
from honeypot import logger
from honeypot.ftp_trap import FTPTrap
from honeypot.http_trap import HTTPTrap
from honeypot.mysql_trap import MySQLTrap
from honeypot.ssh_trap import SSHTrap

TRAPS = [
    # (clase, puerto real, puerto alterno)
    (SSHTrap, 22, 2222),
    (FTPTrap, 21, 2121),
    (HTTPTrap, 80, 8888),
    (MySQLTrap, 3306, 3307),
]

BANNER = r"""
  _   _                       __        __    _       _
 | | | | ___  _ __   ___ _   _\ \      / /_ _| |_ ___| |__
 | |_| |/ _ \| '_ \ / _ \ | | |\ \ /\ / / _` | __/ __| '_ \
 |  _  | (_) | | | |  __/ |_| | \ V  V / (_| | || (__| | | |
 |_| |_|\___/|_| |_|\___|\__, |  \_/\_/ \__,_|\__\___|_| |_|
                         |___/   Honeypot educativo - solo uso local
"""


def main():
    parser = argparse.ArgumentParser(description="HoneyWatch honeypot")
    parser.add_argument("--alt-ports", action="store_true",
                        help="usar puertos alternos (2222, 2121, 8888, 3307)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="interfaz donde escuchan los traps (default: todas)")
    parser.add_argument("--dashboard-host", default="127.0.0.1",
                        help="interfaz del dashboard (default: solo esta PC)")
    parser.add_argument("--dashboard-port", type=int, default=5000)
    parser.add_argument("--clear", action="store_true",
                        help="borrar registros anteriores")
    args = parser.parse_args()

    print(BANNER)
    logger.init_db()
    if args.clear:
        logger.clear_db()
        print("[*] Registros anteriores borrados")

    status = []
    for trap_cls, real_port, alt_port in TRAPS:
        port = alt_port if args.alt_ports else real_port
        trap = trap_cls(port=port, host=args.host)
        trap.start()
        trap.ready.wait(timeout=3)

        if trap.error:
            print(f"[!] {trap.service:<5} puerto {port:<5} NO disponible: {trap.error}")
            status.append({"service": trap.service, "port": port, "active": False})
        else:
            print(f"[+] {trap.service:<5} escuchando en {args.host}:{port}")
            status.append({"service": trap.service, "port": port, "active": True})

        if trap.service == "HTTP":
            # WordPress vive en el mismo puerto que phpMyAdmin (/wp-login.php, /xmlrpc.php)
            if not trap.error:
                print(f"    + WordPress en el mismo puerto: /wp-login.php, /wp-admin, /xmlrpc.php")
            status.append({"service": "WordPress", "port": port, "active": not trap.error})

    if not any(s["active"] for s in status):
        print("\n[!] Ningun trap pudo arrancar. Prueba con --alt-ports")
        return

    from honeypot import alerts
    print("[+] Alertas Telegram: activas" if alerts.is_configured()
          else "[-] Alertas Telegram: desactivadas (configura HW_TELEGRAM_TOKEN y HW_TELEGRAM_CHAT)")

    print(f"\n[*] Dashboard: http://{args.dashboard_host if args.dashboard_host != '0.0.0.0' else '127.0.0.1'}:{args.dashboard_port}")
    print("[*] Esperando conexiones... (Ctrl+C para salir)\n")

    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # no ensuciar la consola
    app = create_app(trap_status=status)
    try:
        app.run(host=args.dashboard_host, port=args.dashboard_port,
                debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        pass
    print("\n[*] HoneyWatch detenido.")


if __name__ == "__main__":
    main()
