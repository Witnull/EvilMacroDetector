import os
import subprocess
import time
from datetime import datetime
import sys
import io
import json
import json5
import re
import asyncio
import psutil
import xml.etree.ElementTree as ET
import uuid
import magic
import pefile
import logging
import networkx as nx
import hashlib
import matplotlib.pyplot as plt
# Prevent errors from being printed to the console
sys.stderr = sys.stderr or io.StringIO()
sys.stdout = sys.stdout or io.StringIO()

import oletools
from oletools.olevba import VBA_Parser, VBA_Scanner
from oletools.msodde import process_file as extract_dde
import trio
from aioresult import ResultCapture
from modules.deobfuscator import deobfuscator
from modules.blacklist import Blacklist
from modules.watchlist import Watchlist
from modules.threat_response import ThreatResponse

# Define Office file extensions
word = ['doc', 'docx', 'docm', 'dot', 'dotx', 'docb', 'dotm']
excel = ['xls', 'xlsx', 'xlsm', 'xlt', 'xlm', 'xltx', 'xltm', 'xlsb', 'xla', 'xlw', 'xlam']
ppt = ['ppt', 'pptx', 'pptm', 'pot', 'pps', 'potx', 'potm', 'ppam', 'ppsx', 'sldx', 'sldm']
# Ref: https://github.com/tehsyntx/loffice/blob/master/loffice.py#L565

"""
Class Parser - def check_* - like parser - extract important information 
Class Analyze - def analyze_* - the detect , correlations 
"""

class Parser:
    def __init__(self, sysinternals_path, log_dir, blacklist, watchlist, log_func):
        """Initialize with paths to Sysinternals tools, log directory, and config directory."""
        self.sysinternals_path = sysinternals_path
        self.log_func = log_func
        self.log_dir = log_dir
        self.blacklist = blacklist
        self.watchlist = watchlist

        #Separated logger
        os.makedirs(self.log_dir, exist_ok=True)
        self.logger = self._setup_logger()
        self.logger.info("Parser initiated...")

        self.config_dir = os.path.dirname(os.path.abspath(__file__))

        # # Paths to Sysinternals tools
        self.sigcheck_exe = os.path.join(sysinternals_path, 'sigcheck.exe')
        self.handle_exe = os.path.join(sysinternals_path, 'handle.exe')
        self.listdlls_exe = os.path.join(sysinternals_path, 'listdlls.exe')
        self.sysmon_exe = os.path.join(sysinternals_path, 'sysmon.exe')

        # # Suspicious 
        self.suspicious_dlls = self.blacklist.suspicious_stuff.get("suspicious_dll", [])
        #self.suspicious_process = self.blacklist.suspicious_stuff.get("suspicious_process", [])
        self.exe_extensions = self.blacklist.suspicious_stuff.get("suspicious_exe_extension", [])
 
        self.office_extensions = word + excel + ppt
        
        self.command_pattern_regexes = []
        # Initialize MIME checker
        self.mime = magic.Magic(mime=True)
        # Load configurations
        self.load_mime_map()
        self.load_scoring_config()

        # Cache for tool results
        self.cache = {}

    def _setup_logger(self):
        """Set up logging with DEBUG level and file handler."""
        logger = logging.getLogger('parser')
        logger.setLevel(logging.DEBUG)
        log_file = os.path.join(self.log_dir, f"parser_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def load_mime_map(self):
        """Load MIME type mappings from JSON file."""
        mime_map_path = os.path.join(self.config_dir, 'mime_map.json')
        with open(mime_map_path, 'r') as f:
            self.mime_map = json.load(f)

    def load_scoring_config(self):
        """Load threat scoring configurations from JSON file."""
        scoring_path = os.path.join(self.config_dir, 'scoring.json5')
        with open(scoring_path, 'r') as f:
            self.scoring = json5.load(f)
    
    def merge_dicts(self, base: dict, *others: dict) -> dict:
        for other in others:
            for key, value in other.items():
                if key not in base:
                    base[key] = value
                    continue

                base_val = base[key]

                # Same type: merge logic
                if isinstance(base_val, dict) and isinstance(value, dict):
                    merge_dicts(base_val, value)  # recursive merge
                elif isinstance(base_val, list) and isinstance(value, list):
                    # Fast set union (no order guaranteed)
                    base[key] = list(set(base_val).union(value))
                elif type(base_val) != type(value):
                    self.log_func(f"Type mismatch on key '{key}': {type(base_val)} != {type(value)} — overwriting.","WARN")
                    base[key] = value
                else:
                    base[key] = value  # overwrite scalar

        return base
    """
    BELOW IS THE MAIN CODE
    that handles the analysis of files, processes, and other components.
    """

    def _get_true_file_extension(self,mime_type):
        for file_ext, mime in self.mime_map.items():
            if mime == mime_type:
                return file_ext
        return ''

    def validate_file_type(self, file_path):
        """
        Validate file type by checking if the file's actual MIME matches expected MIME(s) for its extension.
        Args: file_path (str): Path to the file to validate.
        How: 
            - Get the MIME type of the file using python-magic.
            - Get the file extension and check against the MIME map.
                - If the MIME type matches the expected MIME(s), return True.
                - If the MIME type does not match, return False and a category.
                - If the file extension is not in the MIME map, return False and 'unsupported'.
            
        Returns: (is_valid: bool, category: str, suspicious_score: int)
        """
        try:
            mime_type = self.mime.from_file(file_path)
            file_ext = os.path.splitext(file_path.lower())[1].lstrip('.')
            expected_mimes = self.mime_map.get(file_ext, [])
           
            if not expected_mimes:
                return False, 'unknown', self.scoring.get('unknown_extension', 0)
            if mime_type in expected_mimes:
                if file_ext in self.office_extensions:
                    return True, 'office', self.scoring.get('office', 0)
                elif file_ext in self.exe_extensions:
                    return True, 'exe', self.scoring.get('exe', 20)
                else:
                    return True, 'known', self.scoring.get('other', 0)
            else:
                #true_ext = self._get_true_file_extension(mime_type)
                true_ext = file_ext
                if true_ext in self.office_extensions:
                    self.log_func(f"Got suspicious office file {file_path} with no appropriate MIME, expected {expected_mimes} got {mime_type}","WARN")
                    return True, 'mismatched_office', self.scoring.get('mismatch_office', 20) 
                elif true_ext in self.exe_extensions:
                    self.log_func(f"Got suspicious EXEcutable file  {file_path} with no appropriate MIME, expected {expected_mimes} got {mime_type}","WARN")
                    return True, 'mismatched_exe',self.scoring.get('mismatch_exe', 30) 

            return False, "not_valid", 0
        except PermissionError as e:
            return False, "permission_denied", 0
        except FileNotFoundError as e:
            return False, "not_found", 0
        except Exception as e:
            self.log_func(f"File type validation failed for {file_path}: {str(e)}", "ERROR")
            return False, "not_valid" , self.scoring.get('validation_error', 10)

    def _parse_check_sig(self, cmd_output):
        result = {}
        # Split input into lines and process each line
        for line in cmd_output.strip().split('\n'):
            # Clean the line
            line = line.strip()
            # Skip empty lines or lines without a colon
            if not line or ':' not in line:
                continue
                
            # Split key and value
            key, value = map(str.strip, line.split(':', 1))
            
            # Skip the file path line (it ends with a colon)
            if value.endswith(':'):
                continue
                
            # Standardize key format (lowercase, replace spaces with underscores)
            key = key.lower().replace(' ', '_')
            
            # Convert signing_date to ISO 8601 format if applicable
            if key == 'signing_date':
                try:
                    # Parse the date string (format: "9:38 AM 10/24/2023")
                    dt = datetime.strptime(value, '%I:%M %p %m/%d/%Y')
                    # Convert to ISO 8601 format for JSON
                    value = dt.isoformat()
                except ValueError:
                    # If parsing fails, keep original value
                    pass
            
            # Store value
            result[key] = value
        
        return result

    def check_sig(self,file_path):
        """
        Run Sigcheck to check for digital signatures existence. Lack of confirming if it self sign or not.
        Limited to EXE and DLL files.
        Args: file_path (str): Path to the file to check.
        How: 
           
        Returns: bool
        """
        benchmark_start = time.time()
        is_suspicious = False
        try:
            cmd = [self.sigcheck_exe, "-nobanner", "-accepteula", "-e", str(file_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = result.stdout
            parsed_output = self._parse_check_sig(output)
            # Check if 'verified' key exists and if the file is unsigned
            if 'verified' not in parsed_output:
                self.log_func(f"Failed to parse 'verified' status for {file_path}", "ERROR")
                return False

            if parsed_output['verified'] == 'Unsigned':
                self.log_func(f"Unsigned file detected: {file_path}", "WARN")
                return False

            # Check signing date
            if 'signing_date' in parsed_output:
                try:
                    signing_date = datetime.fromisoformat(parsed_output['signing_date'])
                    days_diff = (datetime.now() - signing_date).days
                    if days_diff < 60:
                        self.log_func(f"File {file_path} signed less than 60 days ago: {parsed_output['signing_date']} considered not signed")
                        return False
                    else:
                        self.log_func(f"Benchmark completed for {file_path} in {time.time() - benchmark_start:.2f} seconds","BM")
                        return True  # Explicitly return True for valid, older signatures
                except ValueError as e:
                    self.log_func(f"Error parsing signing date for {file_path}: {str(e)}")
                    return True
            else:
                self.log_func(f"No signing date found for {file_path}, assuming valid signature")
                return True
        
        except subprocess.CalledProcessError:
            try:
                pe = pefile.PE(file_path, fast_load=True)
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
                if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                    return True  # File has a security directory, likely signed
                return False  # No security directory, likely unsigned
            except Exception as e:
                self.log_func(f"PE file parsing failed for {file_path}: {str(e)}")
                return False
        except PermissionError:
            self.log_func(f"Permission denied for {file_path}")
            return False
        except FileNotFoundError:
            self.log_func(f"File not found: {file_path}")
            return False
        except Exception as e:
            self.log_func(f"Sigcheck failed for {file_path}: {str(e)} Considered as no sig", "ERROR")
            return False

    def _parse_handle_output(self, output):
        """
        Handles the specific format of handle.exe output.
        This version manually parses each field based on the expected positions.
        Args:
            output (str): Output from handle.exe.
        Returns:
            list: A list of JSON strings, each representing one process entry.
        """
        lines = output.strip().split('\n')
        if not lines:
            return []
        
        # Skip header line
        result = []
        
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            
            # Parse the line using regex to handle the specific format
            # Format: Process,PID,User,Handle,Type,Share Flags,Name,Access
            
            # Split on comma but preserve content within parentheses and quotes
            row_pattern = r',(?=(?:[^"]*"[^"]*")*[^"]*$)'
            parts = re.split(row_pattern, line)
            thread_pattern = r'^([^(]+)\((\d+)\):\s*(\d+)'

            thread_match = re.match(thread_pattern, parts[5].strip() if len(parts) > 5 else '')
            
            if len(parts) >= 4:  # Minimum required fields
                row_dict = {
                    'process': parts[0].strip() if len(parts) > 0 else '',
                    'pid': parts[1].strip() if len(parts) > 1 else '',
                    'type': parts[2].strip() if len(parts) > 2 else '',
                    'user': parts[3].strip() if len(parts) > 3 else '',
                    'handle': parts[4].strip() if len(parts) > 4 else '',
                    'name': thread_match.group(1) if thread_match else '',
                    'thread': thread_match.group(3) if thread_match else '',
                    'thread_parent_pid': thread_match.group(2) if thread_match else '',
                    'access': parts[6].strip() if len(parts) > 6 else '',
                }
                
                # Convert PID to int if possible
                try:
                    if row_dict['pid']:
                        row_dict['pid'] = int(row_dict['pid'])
                except (ValueError, TypeError):
                    pass

                result.append(row_dict)

                '''
                # Sample ouput expected
                {
                    "Process": "explorer.exe",
                    "PID": 4136,
                    "Type": "Thread",
                    "User": "NTUX\\null",
                    "Handle": "0x00001ED4",
                    "Name": "explorer.exe",
                    "Thread": "7028",
                    "Thread_Parent_PID": "4136",
                    "Access": "READ_CONTROL|DELETE|SYNCHRONIZE|WRITE_DAC|WRITE_OWNER|THREAD_ALL_ACCESS"
                }
                '''
        
        return result

    async def check_handles(self, file_path_or_pid):
        """Use Handle to check which processes are accessing the file.
        Args:
            file_path_or_pid (str): Path to the file or process or PID of the process to check.
        How:
            - Run handle.exe with the file path as an argument.
            - Capture the output and parse it to extract process information.
        Returns: tuple (bool, dict)

            bool: True if any suspicious processes are found, False otherwise.
            dict: A dictionary containing:
                - output: Parsed output from handle.exe.
                - suspicious_process: List of suspicious processes accessing the file.
                - threat_score: Score based on the analysis.
                - error: Error message if any occurred during execution.
        """
        benchmark_start = time.time()
        results = {
                    'handle_output': [],
                    'handle_suspicious_process': [],
                    'handle_suspicious_system_process': [],
                    'threat_score': 0,
                    }
        is_suspicious = False
        try:
            
            cmd = [self.handle_exe, "-nobanner", "-accepteula", "-a", "-u", "-v", "-g", str(file_path_or_pid)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = result.stdout
            #self.logger.info(f"Handle output for {str(file_path_or_pid)]}: {output}")
            parsed_output = self._parse_handle_output(output)
            results['handle_output'] = parsed_output

            for handle_info in parsed_output:
                file_hash = await self.hash_file_md5(handle_info.get('name', ''))
                if self.watchlist.is_file_in_watchlist(file_hash):
                    self.logger.warning(f"Watchlist file access detected: {handle_info['name']}")
                    is_suspicious = True
                    results['handle_suspicious_process'].append(handle_info)
                    results['threat_score'] += self.scoring.get('suspicious_handle', 30)
                    if handle_info.get('user', '').lower() == "nt authority\\system":
                        self.logger.warning(f"NT AUTHORITY\\SYSTEM process {handle_info['process']} accessing {str(file_path_or_pid)}")
                        self.log_func(f"NT AUTHORITY- SYSTEM process {handle_info['process']} accessing {str(file_path_or_pid)}" , "CRITICAL")
                        results['threat_score'] += self.scoring.get('handle_suspicious_system_process', 30)
                        results['handle_suspicious_system_process'].append(handle_info)
                        self.watchlist.add_process(handle_info['pid'], handle_info)

            self.log_func(f"Handle check completed for {str(file_path_or_pid)} in {time.time() - benchmark_start:.2f} seconds","BM")
            return is_suspicious , results
        except subprocess.CalledProcessError as e:
            return is_suspicious, results
        except PermissionError as e:
            return is_suspicious, results
        except FileNotFoundError as e:
            return is_suspicious, results
        except Exception as e:
            self.logger.error(f"Handle check failed for {str(file_path_or_pid)}: {str(e)} maybe this file not running")
            self.log_func(f"Handle check failed for {str(file_path_or_pid)}: {str(e)} maybe this file not running", "ERROR")
            return is_suspicious, results
    
    async def hash_file_md5(self, file_path):
        """
        Calculate MD5 hash of a file.
        
        Args:
            file_path (str): Path to the file to be hashed
            
        Returns:
            str: Hexadecimal MD5 hash of the file
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            IOError: If there's an error reading the file
        """
        md5_hash = hashlib.md5()
        try:
            with open(file_path, 'rb') as file:
                chunk = await trio.to_thread.run_sync(file.read, 4096)
                while chunk:
                    md5_hash.update(chunk)
                    chunk = await trio.to_thread.run_sync(file.read, 4096)
            return md5_hash.hexdigest()
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {file_path}")
        except IOError as e:
            raise IOError(f"Error reading file {file_path}: {str(e)}") 


    def _parse_listdlls_output(self, output):
        """Parse listdlls output and return structured data"""
        dlls = []
        lines = output.strip().split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines
            if not line:
                i += 1
                continue
            
            # Look for DLL header line (starts with hex address)
            dll_match = re.match(r'^(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(.+)$', line)
            if dll_match:
                base_address = dll_match.group(1)
                size = dll_match.group(2)
                path = dll_match.group(3)
                
                dll_info = {
                    'base_address': base_address,
                    'size': size,
                    'path': path,
                    'verified': None,
                    'publisher': None,
                    'description': None,
                    'product': None,
                    'version': None,
                    'file_version': None,
                    'create_time': None
                }
                
                # Parse the following lines for additional properties
                i += 1
                while i < len(lines) and lines[i].strip():
                    prop_line = lines[i].strip()
                    
                    # Parse various property lines
                    if prop_line.startswith('Verified:'):
                        dll_info['verified'] = prop_line.replace('Verified:', '').strip()
                    elif prop_line.startswith('Publisher:'):
                        dll_info['publisher'] = prop_line.replace('Publisher:', '').strip()
                    elif prop_line.startswith('Description:'):
                        # Handle multiple description lines by taking the first non-empty one
                        if not dll_info['description']:
                            desc = prop_line.replace('Description:', '').strip()
                            if desc:
                                dll_info['description'] = desc
                    elif prop_line.startswith('Product:'):
                        # Handle multiple product lines by taking the first non-empty one
                        if not dll_info['product']:
                            prod = prop_line.replace('Product:', '').strip()
                            if prod:
                                dll_info['product'] = prod
                    elif prop_line.startswith('Version:'):
                        dll_info['version'] = prop_line.replace('Version:', '').strip()
                    elif prop_line.startswith('File version:'):
                        dll_info['file_version'] = prop_line.replace('File version:', '').strip()
                    elif prop_line.startswith('Create time:'):
                        create_time_str = prop_line.replace('Create time:', '').strip()
                        dll_info['create_time'] = create_time_str
                        # Optionally parse to datetime object
                        try:
                            # Parse format like "Fri May 02 07:38:50 2025"
                            dll_info['create_time_parsed'] = datetime.strptime(
                                create_time_str, '%a %b %d %H:%M:%S %Y'
                            ).isoformat()
                        except ValueError:
                            # Keep original string if parsing fails
                            dll_info['create_time_parsed'] = create_time_str
                    
                    i += 1
                
                dlls.append(dll_info)
            else:
                i += 1
        
        return dlls
    
    def check_dlls(self, pid):
        """Analyze DLLs loaded by a process for suspicious behavior.
        Args:
            pid (int): Process ID to analyze.
        How:
            - Run listdlls.exe with the PID as an argument.
            - Capture the output and parse it to extract DLL information.
            - Check each DLL against known suspicious DLLs and system paths or unsigned.

        Returns: tuple (bool, dict)
            bool: True if any suspicious DLLs are found, False otherwise.
            dict: A dictionary containing:
                - output: Parsed output from listdlls.exe.
                - suspicious_dlls: List of suspicious DLLs found.
                - process_info: Information about the process being analyzed.
                - error: Error message if any occurred during execution.
                - threat_score: Score based on the analysis findings.
        
        """
        benchmark_start = time.time()
        results = {
            'listdlls_output': [],
            'suspicious_dlls': [],
            'threat_score': 0
        }
        is_suspicious = False

        try:
            cmd = [self.listdlls_exe, '-accepteula', '-u', '-nobanner', str(pid)]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = result.stdout
            parsed_output = self._parse_listdlls_output(output)

            # """
            # # Sample output expected
            # 0x00000000b6640000  0x27000   C:\Path\to\suspicious.dll
            #                 Verified:       Unsigned
            #                 Publisher:      Microsoft Corporation
            #                 Description:    Xxxx
            #                 Product:        Xxxx
            #                 Description:    Xxxx
            #                 Product:        Xxxx
            #                 Product:        Xxxx
            #                 Version:        10.0.1566.19041
            #                 File version:   10.0.1.19041
            #                 Create time:    Fri May 02 07:38:50 2025
            # """

            results['listdlls_output'] = parsed_output
            dlls = parsed_output

            system_paths = [os.path.normpath(os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), p)).lower()
                            for p in ['System32', 'SysWOW64']]

            for dll in dlls:
                dll_path = dll['path']
                dll_name = os.path.basename(dll_path).lower()
                if dll_name in self.suspicious_dlls:
                    self.logger.warning(f"Suspicious DLL name: {dll_name}")
                    dll['is_suspicious'] = True
                    is_suspicious = True
                    results['suspicious_dlls'].append(dll)
                    results['threat_score'] += self.scoring.get('suspicious_dll', 30)


                dll_dir = os.path.normpath(os.path.dirname(dll_path)).lower()
                if not any(dll_dir.startswith(sys_path) for sys_path in system_paths):
                    self.logger.warning(f"DLL from non-system path: {dll_path}")
                    dll['is_suspicious'] = True
                    dll['reason'] = 'Non-system path'
                    is_suspicious = True
                    results['suspicious_dlls'].append(dll)
                    results['threat_score'] += self.scoring.get('non_system_dll', 30)

                if dll.get('verified').lower() == 'unsigned':
                    self.logger.warning(f"Unsigned DLL: {dll_path}")
                    dll['is_suspicious'] = True
                    dll['reason'] = 'Unsigned'
                    is_suspicious = True
                    results['suspicious_dlls'].append(dll)
                    results['threat_score'] += self.scoring.get('unsigned_file', 30)

            self.log_func(f"ListDLLs check completed for PID {pid} in {time.time() - benchmark_start:.2f} seconds","BM")
            return is_suspicious, results
        except PermissionError as e:
            return is_suspicious, results
        except FileNotFoundError as e:
            return is_suspicious, results
        except Exception as e:
            self.logger.error(f"Error analyzing DLLs for PID {pid}: {str(e)}")
            self.log_func(f"Error analyzing DLLs for PID {pid}: {str(e)}", "ERROR")
            return is_suspicious, results

    def check_sysmon_events(self, file_path):
        """Check Sysmon logs for events related to the file."""
        try:

            # #cmd = ['wevtutil', 'qe', 'Microsoft-Windows-Sysmon/Operational', '/q:*[System[(EventID=1)]]', '/c:10', '/rd:true', '/f:xml']
            # #result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            # xml_output = ""#result.stdout
            # root = ET.fromstring(f"<Events>{xml_output}</Events>")
            # for event in root.findall('.//Event'):
            #     data = event.findall('.//Data')
            #     for d in data:
            #         if d.get('Name') == 'Image' and file_path.lower() in d.text.lower():
            #             self.logger.warning(f"Sysmon event detected for {file_path}: {ET.tostring(event, encoding='unicode')}")
            #             return True, ET.tostring(event, encoding='unicode')
            # self.logger.info(f"Sysmon event check {results}")

            return False, "No Sysmon events found"
        except (subprocess.CalledProcessError, ET.ParseError) as e:
            self.logger.error(f"Sysmon event check failed: {str(e)}")
            self.log_func(f"Sysmon event check failed: {str(e)}", "ERROR")
            return False, str(e)

   
    def check_macros(self, file_path):

        """Analyze macros in Office files using oletools (olevba).
        Args:
            file_path (str): Path to the Office file to analyze.
        How:
            - Use VBA_Parser from olevba to extract macros.
            - Check for DDE links (https://www.wired.com/story/russia-fancy-bear-hackers-microsoft-office-flaw-and-nyc-terrorism-fears/)
            - And analyze macros for suspicious keywords. 
        Returns: dict
            - macros: List of macros found in the file.
            - dde: List of DDE links found in the file.
            - keywords: Dictionary of keywords found in the macros.
            - errors: List of errors encountered during analysis.
            - threat_score: Total threat score based on findings.
            - is_suspicious: True if any suspicious activity is detected.
            - has_macros: True if macros are present in the file.
            - ioc: True if any IOCs are detected.
            - vba_obfuscated: True if any obfuscated VBA code is detected.
            - autoexec: True if any AutoExec macros are detected.

        """
        benchmark_start = time.time()
        results = {
            'macros':[],
            'dde': [],
            'threat_score': 0,
            'has_macros': False,
            'ioc': False,
            'vba_obfuscated': False,
            'autoexec': False
        }
        is_suspicious = False
        threat_score = 0
        try:
            self.logger.debug(f"Starting macro analysis for {file_path}")
            try:
                vba_parser = VBA_Parser(filename=file_path)
            except Exception as e:
                self.logger.error(f"Failed to initialize VBA parser for {file_path}: {str(e)}")
                self.log_func(f"Failed to initialize VBA parser for {file_path}: {str(e)}", "ERROR")
                return is_suspicious, results


            if not vba_parser.detect_vba_macros():
                self.logger.info(f"No macros found in {file_path}")
                vba_parser.close()
                return is_suspicious, results
                
            results['has_macros'] = True
          
            try:
                dde_results = extract_dde(file_path)
                if dde_results:
                    self.logger.warning(f"DDE links detected in {file_path}: {dde_results}")
                    results['dde'] = dde_results
                    is_suspicious = True
                    threat_score += self.scoring.get('dde_link', 20)
            except Exception as e:
                self.logger.error(f"DDE analysis failed for {file_path}: {str(e)}")
                self.log_func(f"DDE analysis failed for {file_path}: {str(e)}", "ERROR")

            try:
                for (filename, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                    macro_entry = {
                        'filename': filename,
                        'stream_path': stream_path,
                        'vba_filename': vba_filename,
                        'macros': vba_code,
                    }
                    results['macros'].append(macro_entry)

                vba_analyse_results = vba_parser.analyze_macros()
                olevba_analyse_results = self._analyse_olevba_results(vba_analyse_results)
                threat_score += olevba_analyse_results['threat_score']
                self.merge_dicts(results,olevba_analyse_results)

                # Deobfuscate macros if present
                if olevba_analyse_results.get('vba_obfuscated', False):
                    deobufus_await = trio.run(self.deobfuscate_macros, file_path)
                    has_deobfuscated, deobfuscation_results = deobufus_await
                    threat_score += deobfuscation_results.get('threat_score', 0)
                    self.merge_dicts(results, deobfuscation_results)

                results['threat_score'] =  threat_score

            except PermissionError as e:
                return is_suspicious, results
            except FileNotFoundError as e:
                return is_suspicious, results
            except Exception as e:
                self.logger.error(f"Macro scanning failed for {file_path}: {str(e)}")
                self.log_func(f"Macro scanning failed for {file_path}: {str(e)}", "ERROR")

            vba_parser.close()
            self.log_func(f"Macro analysis completed for {file_path} in {time.time() - benchmark_start:.2f} seconds", "BM")
            return is_suspicious, results
        except Exception as e:
            self.logger.error(f"Unexpected error in macro analysis for {file_path}: {str(e)}")
            self.log_func(f"Unexpected error in macro analysis for {file_path}: {str(e)}", "ERROR")
            return is_suspicious, results


    def _analyse_olevba_results(self, vba_analyse_results):

        results = {
            'keywords': [],
            'threat_score': 0,
            'autoexec': False,
            'ioc': False,
            'vba_obfuscated': False
        }

        for kw_type, keyword, description in vba_analyse_results:
            # types 'AutoExec', 'Suspicious', 'IOC'
            # https://github.com/decalage2/oletools/blob/master/oletools/olevba.py#L2594
            
            if 'obfuscate' in description.lower():
                results['vba_obfuscated'] = True
                results["keywords"].append(f"{keyword}: vba_obfuscated@{description}")
                results['threat_score'] += self.scoring.get('vba_obfuscated', 30)
                continue

            if "command" in description.lower():
                results["keywords"].append(f"{keyword}: command@{description}")
                is_suspicious = True
                results['threat_score'] += self.scoring.get('command', 20)
                continue

            if kw_type == 'Suspicious':
                is_suspicious = True
                results["keywords"].append(f"{keyword}: suspicious@{description}")
                results['threat_score'] += self.scoring.get('suspicious_keyword', 10)
                
            if kw_type == 'AutoExec':
                results["keywords"].append(f"{keyword}: autoexec@{description}")
                is_suspicious = True
                results['autoexec'] = True
                results['threat_score'] += self.scoring.get('autoexec', 30)
            
            if kw_type == 'IOC':
                is_suspicious = True
                results['ioc'] = True
                if "ip" in description.lower():
                    results["keywords"].append(f"{keyword}: ip@{description}")
                    self.log_func(f"Suspicious IP detected in macro: {description}", "CRITICAL")
                elif "url" in description.lower():
                    results["keywords"].append(f"{keyword}: url@{description}")
                    self.log_func(f"Suspicious URL detected in macro: {description}", "CRITICAL")
                elif "executable file" in description.lower():
                    results["keywords"].append(f"{keyword}: executable@{description}")
                    self.log_func(f"Suspicious executable file detected in macro: {description}", "CRITICAL")
                else:
                    results["keywords"].append(f"{keyword}: ioc@{description}")
                    self.log_func(f"Suspicious IOC detected in macro: {description}", "CRITICAL")
                results['threat_score'] += self.scoring.get('ioc', 40)     
            


        return results      

    def deobfuscate_macros(self, file_path):
        """Deobfuscate macros in Office files
        """
        results = {
            'deobfuscated_macro': {},
            'threat_score': 0,
        }
        try:
            self.logger.info(f"Begin deobfuscate {file_path}")

            output_file = os.path.join(self.log_dir, f"Deofuscated_{os.path.basename(file_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
            content = deobfuscator(file_path)

            with open(output_file, 'w') as f:
                f.write(content)

            vba_analyse_results =  VBA_Scanner(content).scan(include_decoded_strings = True)
            olevba_analyse_results = self._analyse_olevba_results(vba_analyse_results)
            results['deobfuscated_macro'] = content
            threat_score += olevba_analyse_results['threat_score']
            self.merge_dicts(results, olevba_analyse_results)
            results['threat_score'] = threat_score
            return True, results
        except Exception as e:
            self.logger.error(f"Deobfuscation failed for {file_path}: {str(e)}")
            self.log_func(f"Deobfuscation failed for {file_path}: {str(e)}", "ERROR")
            return False, results

