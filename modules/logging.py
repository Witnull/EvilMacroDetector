
import time
import servicemanager
from pathlib import Path

log_file = 

def _log(message, severity="INFO"):
    """Log messages to files by severity."""
    tag = f"[{severity}]"
    log_message = f"{tag} {message}"
    try:
        with open(log_file + "FULL.log", "a") as f:
            f.write(f"[{time.ctime()}] {log_message}\n")
        with open(log_file + f"_{severity}.log", "a") as f:
            f.write(f"[{time.ctime()}] {log_message}\n")
    except Exception as e:
        servicemanager.LogErrorMsg(f"Logging failed: {str(e)}")
    
