"""
HoneyWatch - alerts.py
Envia alertas al celular a traves de un bot de Telegram (gratis).

Configuracion (en PowerShell, antes de ejecutar main.py):
    $env:HW_TELEGRAM_TOKEN = "token que te da @BotFather"
    $env:HW_TELEGRAM_CHAT  = "tu chat_id"

Prueba rapida (envia un mensaje de prueba):
    python -m honeypot.alerts
"""

import json
import os
import threading
import urllib.request

def _get_setting(name):
    """Lee la variable del entorno; si no esta (pasa con terminales abiertas
    antes de guardarla con setx), la busca en el registro de Windows."""
    value = os.environ.get(name, "").strip()
    if not value and os.name == "nt":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                value = str(winreg.QueryValueEx(key, name)[0]).strip()
        except OSError:
            value = ""
    return value


TOKEN = _get_setting("HW_TELEGRAM_TOKEN")
CHAT_ID = _get_setting("HW_TELEGRAM_CHAT")


def is_configured():
    return bool(TOKEN and CHAT_ID)


def _send(text):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    data = json.dumps({"chat_id": CHAT_ID, "text": text}).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode()).get("ok", False)
    except Exception as e:
        print(f"[alerts] No se pudo enviar a Telegram: {e}")
        return False


def notify(text):
    """Envia el mensaje en un hilo aparte para no frenar los traps."""
    if is_configured():
        threading.Thread(target=_send, args=(text,), daemon=True).start()


def find_chat_id():
    """Busca el chat_id en los ultimos mensajes que recibio el bot."""
    if not TOKEN:
        print("Primero configura el token:  $env:HW_TELEGRAM_TOKEN = \"tu_token\"")
        return
    url = f"https://api.telegram.org/bot{TOKEN}/getUpdates"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:
        print(f"No se pudo consultar Telegram (revisa el token): {e}")
        return

    chats = {}
    for upd in data.get("result", []):
        msg = upd.get("message") or upd.get("channel_post") or {}
        chat = msg.get("chat")
        if chat:
            chats[chat["id"]] = chat.get("first_name") or chat.get("title") or ""

    if not chats:
        print("El bot todavia no tiene mensajes.\n"
              "1) Abre tu bot en Telegram y pulsa INICIAR (o escribe /start)\n"
              "2) Escribele cualquier cosa, por ejemplo: hola\n"
              "3) Vuelve a ejecutar este comando")
        return
    for cid, name in chats.items():
        print(f"chat_id encontrado: {cid}  ({name})")
    print(f'\nAhora ejecuta:  $env:HW_TELEGRAM_CHAT = "{next(iter(chats))}"')


if __name__ == "__main__":
    import sys
    if "--chat-id" in sys.argv:
        find_chat_id()
    elif not is_configured():
        print("Faltan las variables HW_TELEGRAM_TOKEN y HW_TELEGRAM_CHAT.")
    elif _send("✅ HoneyWatch: prueba de alerta. Si ves esto, todo funciona."):
        print("Mensaje enviado. Revisa Telegram en tu celular.")
    else:
        print("Telegram rechazo el mensaje. Revisa el token y el chat_id.")
