import os
from datetime import datetime
import psutil
import shutil
import subprocess
from modules.remove_vba import clean_office_macro
import json
import trio

class ThreatResponse:
    """Handles automated responses to detected threats."""
    
    def __init__(self, log_func, log_dir, parser):
        self.log_func = log_func
        self.quarantine_dir = os.path.join(log_dir, "Quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.parser = parser

    def quarantine_file(self, file_path):
        """Move a suspicious file to the quarantine directory."""
        try:
            dest_path = os.path.join(self.quarantine_dir, os.path.basename(file_path) + f".quarantine_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            shutil.move(file_path, dest_path)
            self.log_func(f"Quarantined file: {file_path} to {dest_path}", "ALERT")
      
        except Exception as e:
            self.log_func(f"Failed to quarantine {file_path}: {str(e)}", "ERROR")
    

    def terminate_process(self, pid_or_file, type_="pid"):
        """Terminate a suspicious process."""
        try:
            if type_ == "pid":
                pid = pid_or_file
                proc = psutil.Process(pid)
                proc.terminate()
                self.log_func(f"Terminated process PID {pid}", "ALERT")
            elif type_ == "handle":
                handles = pid_or_file
                for handle in handles:
                    proc = psutil.Process(handle['pid'])
                    proc.terminate()
                    self.log_func(f"Terminated process PID {handle['pid']}", "ALERT")

     
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.log_func(f"Failed to terminate PID {pid}: {str(e)}", "ERROR")
     


    def block_ip(self, ip_address):
        """Add a firewall rule to block a suspicious IP (requires admin)."""
        try:
            rule_name = f"Block_{ip_address}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=out", "action=block", f"remoteip={ip_address}"]
            subprocess.run(cmd, check=True)
            self.log_func(f"Blocked IP {ip_address} with firewall rule {rule_name}", "ALERT")
    
        except subprocess.CalledProcessError as e:
            self.log_func(f"Failed to block IP {ip_address}: {str(e)}", "ERROR")
     
    async def remove_vba_macro(self, file_path):
        """Remove VBA macros from an Office document."""
        try:
            x = clean_office_macro(file_path)
            res, path = x
            if not res:
                self.log_func(f"Failed to remove VBA macros from {file_path}: {path}", "ERROR")
                return
            self.quarantine_file(file_path)
            self.log_func(f"Removed VBA macros from {file_path} -> {path}", "ALERT")
          
        except Exception as e:
            self.log_func(f"Failed to remove VBA macros from {file_path}: {str(e)}", "ERROR")
         

    def export_analysis_results(self, file_path, results):
        """Export analysis results to a file."""
        try:
            export_path = os.path.join(self.quarantine_dir, os.path.basename(file_path) + f"_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
            with open(export_path, 'w') as f:
                json.dump(results, f)
            self.log_func(f"Exported analysis results to {export_path}", "ALERT")
            return True, export_path
        except Exception as e:
            self.log_func(f"Failed to export analysis results: {str(e)}", "ERROR")
            return False, str(e)
