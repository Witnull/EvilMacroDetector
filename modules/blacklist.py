import json
import json5
from datetime import datetime
import os

class Blacklist:
    """ class to track blacklisted IP addresses, DLLs, and processes """
    def __init__(self, log_dir, log_func):
        self.last_saved = datetime.now()
        self.save_dir = log_dir
        self.log_func = log_func
        os.makedirs(self.save_dir, exist_ok=True)
        self.file_path = os.path.join( os.path.dirname(os.path.abspath(__file__)),'blacklist.json') #os.path.join(self.save_dir, "blacklist.json")
        self.exclusions_path = os.path.join( os.path.dirname(os.path.abspath(__file__)),'exclusions.json')
        # List of blacklisted 
        self.suspicious_stuff = {
            # Suspicious IP addresses
            "suspicious_ip": [],
            # Suspicious Ports
            "suspicious_port": [],
            # Suspicious DLLs 
            "suspicious_dll":['ole32.dll', 'vbscript.dll', 'jscript.dll'],
            # Suspicious processes
            "suspicious_process": [
                'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', #cmdline
                'calc.exe','mspaint.exe','notepad.exe' # non internet processes
                ],
            # Office processes
            "office_process": ['winword.exe', 'excel.exe', 'powerpnt.exe'],
            # Suspicious file extensions
            "suspicious_exe_extension": ['exe', 'dll','py', 'pl', 'bat', 'ps1', 'sh', 'cmd', 'bin', 'com', 'vbs', 'js'],
            # Suspicious commands
            "suspicious_commands": ['cmd', 'powershell', 'net', 'reg', 'taskkill', 'sc', 'wmic', 'curl'],
            # Suspicuous Office extensions
            "suspicious_office_extension": ["docm", "dotm", "xlm", "xlam", "xlsm", "xltm", "potm",  "ppsm", "pptm", "sldm", "ppam"],
            # Ref: https://community.spiceworks.com/t/ms-office-documents-with-macros-easy-way-to-identify-and-filter/952121/7
            "suspicious_cmd_args": ["-NoProfile", "-WindowStyle Hidden", "-Passthru"],
            "timestamp": None
        }

        self.exclusions={}

        if not os.path.exists(self.file_path):
            self.save_to_json() # initial save
        else:
            self.load_from_json()
            # Load existing blacklist
        self.load_exclusions()
    
    def load_exclusions(self):
        """Load exclusion configurations from JSON file."""
        with open(self.exclusions_path, 'r') as f:
            self.exclusions = json5.load(f)

    def save_to_json(self, force=False):
        """ Save the blacklist to a JSON file """
        if not force and (datetime.now() - self.last_saved).total_seconds() < 60:
            return False
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.suspicious_stuff["timestamp"] = timestamp
            with open(self.file_path, 'w') as f:
                json.dump(self.suspicious_stuff, f)
            self.last_saved = datetime.now()
            return True
        except Exception as e:
            return False
    
    def load_from_json(self):
        """ Load the blacklist from a JSON file """
        try:
            with open(self.file_path, 'r') as f:
                self.suspicious_stuff = json.load(f)
            return True
        except Exception as e:
            return False



