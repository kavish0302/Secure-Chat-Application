import os

LOG_FILE = "message_log.txt"

def clear_log():
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)

def log_message(username, message: str, encrypted: str):
    with open(LOG_FILE, "a") as f:
        f.write(f"{message} : {encrypted}\n")
