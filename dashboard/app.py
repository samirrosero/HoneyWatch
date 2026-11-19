"""
HoneyWatch - dashboard/app.py
Dashboard Flask. El HTML consulta /api/stats y /api/attempts cada pocos segundos.
"""

import os
import sys

from flask import Flask, jsonify, render_template, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from honeypot import logger  # noqa: E402


def create_app(trap_status=None):
    """trap_status: lista de dicts {service, port, active} que muestra main.py."""
    app = Flask(__name__)
    app.config["TRAP_STATUS"] = trap_status or []

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/attempts")
    def attempts():
        limit = min(int(request.args.get("limit", 50)), 500)
        return jsonify(logger.get_recent(limit))

    @app.route("/api/stats")
    def stats():
        data = logger.get_stats()
        data["traps"] = app.config["TRAP_STATUS"]
        return jsonify(data)

    return app


if __name__ == "__main__":
    # Permite abrir solo el dashboard (sin traps) para revisar datos guardados
    logger.init_db()
    create_app().run(host="127.0.0.1", port=5000, debug=False)
