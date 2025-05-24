import asyncio
import hashlib
import io
import json
import json5
import logging
import magic
import matplotlib.pyplot as plt
import networkx as nx
import os
import pefile
import psutil
import re
import subprocess
import sys
import time
import trio
import xml.etree.ElementTree as ET
from aioresult import ResultCapture
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, wrpcap,DNS, DNSQR, Raw
from scapy.main import load_layer
load_layer("tls")
from scapy.layers.tls.record import TLS
import uuid
# Prevent errors from being printed to the console
sys.stderr = sys.stderr or io.StringIO()
sys.stdout = sys.stdout or io.StringIO()
# OLE related imports
import oletools
from oletools.olevba import VBA_Parser, VBA_Scanner
from oletools.msodde import process_file as extract_dde

# Local modules
from modules.blacklist import Blacklist
from modules.watchlist import Watchlist
from modules.deobfuscator import deobfuscator
from modules.parser import Parser
from modules.threat_response import ThreatResponse
from modules.watchlist import Watchlist



# Define Office file extensions
word = ['doc', 'docx', 'docm', 'dot', 'dotx', 'docb', 'dotm']
excel = ['xls', 'xlsx', 'xlsm', 'xlt', 'xlm', 'xltx', 'xltm', 'xlsb', 'xla', 'xlw', 'xlam']
ppt = ['ppt', 'pptx', 'pptm', 'pot', 'pps', 'potx', 'potm', 'ppam', 'ppsx', 'sldx', 'sldm']
# Ref: https://github.com/tehsyntx/loffice/blob/master/loffice.py#L565

"""
Class Parser - def check_* - like parser - extract important information 
Class Analyze - def analyze_* - the detect , correlations 
"""

class Analyzer:
    def __init__(self, sysinternals_path, log_dir, blacklist, watchlist, log_func):
        """Initialize with paths to Sysinternals tools, log directory, and config directory."""
        self.log_func = log_func
        self.log_dir = log_dir
        self.blacklist = blacklist
        self.watchlist = watchlist

        self.threat_response = ThreatResponse(self.log_func, self.log_dir)
        self.parser = Parser(sysinternals_path, self.log_dir, self.blacklist, self.watchlist, self.log_func)
        
        #Separated logger
        os.makedirs(self.log_dir, exist_ok=True)
        self.logger = self._setup_logger()
        self.logger.info("Analyzer initiated...")

        self.config_dir = os.path.dirname(os.path.abspath(__file__))

        # # Suspicious 
        self.suspicious_dlls = self.blacklist.suspicious_stuff.get("suspicious_dll", [])
        self.suspicious_process = self.blacklist.suspicious_stuff.get("suspicious_process", [])
        self.office_processes = self.blacklist.suspicious_stuff.get("office_process", [])
        self.suspicious_ip = self.blacklist.suspicious_stuff.get("suspicious_ip", [])
        self.suspicious_ports = self.blacklist.suspicious_stuff.get("suspicious_port", [])
        self.exe_extensions = self.blacklist.suspicious_stuff.get("suspicious_exe_extension", [])
        self.suspicious_commands = self.blacklist.suspicious_stuff.get("suspicious_commands", [])
        self.suspicious_cmd_args = self.blacklist.suspicious_stuff.get("suspicious_cmd_args", [])

        self.exclusions = self.blacklist.exclusions
        self.office_extensions = word + excel + ppt
        self.exclude_command_pattern_regexes = []
        self.compile_command_patterns()
        self.load_scoring_config()

    def _setup_logger(self):
        """Set up logging with DEBUG level and file handler."""
        logger = logging.getLogger('analyzer')
        logger.setLevel(logging.DEBUG)
        log_file = os.path.join(self.log_dir, f"analyzer_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def compile_command_patterns(self):
        self.exclude_command_pattern_regexes = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.exclusions.get('command_patterns', [])
        ]
        self.logger.debug(f"Compiled command patterns: {self.exclude_command_pattern_regexes}")

    def load_scoring_config(self):
        """Load threat scoring configurations from JSON file."""
        scoring_path = os.path.join(self.config_dir, 'scoring.json5')
        with open(scoring_path, 'r') as f:
            self.scoring = json5.load(f)

    """
    Anlyzing part of the file
    Handle the correlations and add to watch list the suspicious stuff
    Like: ip, file, process ...
    """

    def _analyzing_dlls(self, pid):
        proc_info = psutil.Process(pid)
        threat_score = 0
        dll_results ={}
        if proc_info:
            has_suspicious_dll, dll_results = self.parser.check_dlls(proc_info.pid)
            if has_suspicious_dll:
                for dll in dll_results.get('suspicious_dlls', []):
                    self.watchlist.add_process(proc_info.pid, dll)
                    self.logger.info(f"Sus process {proc_info.pid} is accessing suspicious DLL: {dll['path']}")
                    self.log_func(f"Sus process {proc_info.pid} is accessing suspicious DLL: {dll['path']}", "CRITICAL")
                    threat_score += self.scoring.get('suspicious_dll_with_suspicious_processs', 40) 

        return dll_results, threat_score


    async def analyze_office(self, file_path):
        """Analyze Office files and summarize findings.
        Args:
            file_path (str): Path to the Office file to analyze.
        How:
            - Check if the file is an Office file.
            - Check for suspicious macros.
            - Check DLLs loaded by Office processes.
        Returns: dict 
        """
    
        results = {
           
            'threat_score': 0,
            'is_dangerous': False,
            'has_macros': False,
            'ioc': False,
            'vba_obfuscated': False,
            'autoexec': False
        }
        is_suspicious = False
        threat_score = 0

        try:
            is_valid, file_type, type_score = self.parser.validate_file_type(file_path)
            threat_score += type_score
            if not is_valid:
                self.logger.info(f"Invalid file type for {file_path}: {file_type}")
                self.log_func(f"Invalid file type for {file_path}: {file_type}", "ERROR")
                return is_suspicious, results

            self.logger.info(f"Analyzing Office file: {file_path}")

            has_suspicious_macro, macro_results = self.parser.check_macros(file_path)
            threat_score += macro_results.get('threat_score', 0)
            results.update(macro_results)

            has_suspicious_handle, handle_output = self.parser.check_handles(file_path)
            threat_score += handle_output.get('threat_score', 0)
            results.update(handle_output)

            #has_sysmon_event, sysmon_output = self.check_sysmon_events(file_path)
            # results['threat_score'] += sysmon_output.get('threat_score', 0)
            # results.update(sysmon_output)
            
            # self.logger.debug(f"Macro analysis results: {results}")

            # Analyze deeper if suspicious macros are found
            """
            Check correlations 
            How:
                - If any suspicious processes in Handle are found, analyze their DLLs for further threats.
                - Check in current watchlist 
            """

             # Check dlls
            has_suspicious_dll, dll_results = self.parser.check_dlls(file_path)
            threat_score += dll_results.get('threat_score', 0)
            results.update(dll_results)
            if has_suspicious_dll:
                for dll in dll_results.get('suspicious_dlls', []):
                    self.watchlist.add_process(proc_info.pid, dll)
                    self.logger.info(f"Process {proc_info.pid} is accessing suspicious DLL: {dll['path']}")
                    self.log_func(f"Process {proc_info.pid} is accessing suspicious DLL: {dll['path']}", "CRITICAL")
                    threat_score += self.scoring.get('suspicious_dll', 30)


            if macro_results.get('has_macros', False) or has_suspicious_macro: 
                # Check Handle exist then file is being used ;
                # Can only check parent proc - not that useful
                # if the file is accessed by any suspicious processes, then  further analyze their dlls
                for handle_info in handle_output.get('suspicious_system_process', []):
                    self.logger.info(f"File {file_path} is accessed by SYSTEM suspicious process {handle_info['Process']}")
                    self.log_func(f"File {file_path} is accessed by SYSTEM suspicious process {handle_info['Process']}", "CRITICAL")
                    dlls_results , dll_score = self._analyzing_dlls(handle_info)
                    threat_score += dll_score 
                    results.update(dlls_results)

                for handle_info in handle_output.get('suspicious_process', []):
                    self.logger.info(f"File {file_path} is accessed by suspicious process {handle_info['Process']}")
                    dlls_results , dll_score = self._analyzing_dlls(handle_info)
                    threat_score += dll_score 
                    results.update(dlls_results)
                #########
            results['threat_score'] = threat_score     # if suspicious / mostly will > 70      
            return is_suspicious, results

        except Exception as e:
            self.logger.error(f"Unexpected error analyzing Office file {file_path}: {str(e)}")
            self.log_func(f"Unexpected error analyzing Office file {file_path}: {str(e)}", "ERROR")
            return is_suspicious, results

    async def analyze_exe(self, file_path):
        """Analyze executable files for suspicious behavior.
        Args:
            file_path (str): Path to the executable file to analyze.
        How:
            - Check file properties (e.g., signature, path).
            - Check dlls loaded
            - Check handles for suspicious file it run , then check their dlls
            - Check for connections to the internet.
        """
        results = {
            'sigcheck': {},
            'handles': {},
            'dlls': {},
            'procdump': {},
            'sysmon': {},
            'threat_score': 0,
            'is_dangerous': False,
        }

        is_suspicious = False
        threat_score = 0
        try:
            is_valid, file_type, type_score = self.parser.validate_file_type(file_path)
            threat_score += type_score
            if not is_valid:
                self.logger.info(f"Invalid file type for {file_path}: {file_type}")
                self.log_func(f"Invalid file type for {file_path}: {file_type}", "ERROR")
                return is_suspicious ,results

            self.logger.info(f"Analyzing EXEcutable file: {file_path}")

            # Check file location
            file_dir = os.path.normpath(os.path.dirname(file_path)).lower()
            system_paths = [os.path.normpath(os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), p)).lower()
                            for p in ['System32', 'SysWOW64', 'Program Files', 'Program Files (x86)']]
            temp_paths = [os.path.normpath(os.path.expandvars(p)).lower() for p in ['%TEMP%', '%APPDATA%']]
            # Check if the file is in a non-standard path
            if not any(file_dir.startswith(sys_path) for sys_path in system_paths):
                self.logger.warning(f"EXE in non-standard path: {file_path}")
                threat_score += self.scoring.get('non_standard_path_exe', 10)
                is_suspicious = True

            if any(file_dir.startswith(temp_path) for temp_path in temp_paths):
                self.logger.warning(f"EXE in temporary directory: {file_path}")
                threat_score += self.scoring.get('temp_directory_exe', 20)
                is_suspicious = True

            # Run sigcheck
            has_signature = self.parser.check_sig(file_path)
            results['sigcheck'] = has_signature
            if not has_signature:
                self.logger.warning(f"Unsigned EXE: {file_path}")
                is_suspicious = True
                threat_score += self.scoring.get('unsigned_file', 20)

            # Check handles and dlls
            has_suspicious_handle, handle_output = self.parser.check_handles(file_path)
            threat_score += handle_output.get('threat_score', 0)
            results.update(handle_output)

            if has_suspicious_handle: # then the file is being used by some process and in watchlist
                for handle_info in handle_output.get('suspicious_process', []):
                    self.logger.info(f"File {file_path} is accessed by suspicious process {handle_info['process']}")
                    dlls_results , dll_score = self._analyzing_dlls(handle_info['pid'])
                    threat_score += dll_score 
                    results.update(dlls_results)

                for handle_info in handle_output.get('suspicious_system_process', []):
                    self.logger.info(f"File {file_path} is accessed by SYSTEM suspicious process {handle_info['process']}")
                    self.log_func(f"File {file_path} is accessed by SYSTEM suspicious process {handle_info['process']}", "CRITICAL")
                    dlls_results , dll_score = self._analyzing_dlls(handle_info['pid'])
                    threat_score += dll_score 
                    results.update(dlls_results)

            # Check Sysmon events
            # has_sysmon_event, sysmon_output = self.parser.check_sysmon_events(file_path)
            # results['sysmon'] = sysmon_output
            # if has_sysmon_event:
            #     self.logger.warning(f"Sysmon event detected for {file_path}")
            #     is_suspicious = True
            #     threat_score += self.scoring.get('sysmon_event_exe', 10)

            results['threat_score'] = threat_score
            return is_suspicious, results

        except Exception as e:
            self.logger.error(f"Unexpected error analyzing EXE {file_path}: {str(e)}")
            self.log_func(f"Unexpected error analyzing EXE {file_path}: {str(e)}", "ERROR")
            return is_suspicious, results

    def is_ip_suspicious(self, ip, port):
        if ip in self.exclusions.get('ip', []) or port in self.exclusions.get('ports', []):
            self.logger.info(f"IP {ip} or port {port} is in exclusion list, skipping analysis")
            self.log_func(f"IP {ip} or port {port} is in exclusion list, skipping analysis", "IGNORED")
            return False
        if ip in self.suspicious_ip or port in self.suspicious_ports or ip in self.watchlist.watchlist_ip:
            self.log_func(f"Process {proc_name}-{pid} has suspicious connection to {raddr} on port {conn.raddr.port}", "CRITICAL")
            self.logger.critical(f"Process {proc_name}-{pid} has suspicious connection to {raddr} on port {conn.raddr.port}")
            return True
        return False

    async def analysis_process(self, pid, is_child=False):
        """Analyze a process for suspicious behavior."""
        results = {
            'suspiscious_ip': [],
            'suspicious_ports': [],
            'connect_to_inet':[],
            'threat_score': 0,
            'is_dangerous': False,
        }
        is_suspicious = False
        threat_score = 0
        try:
            self.logger.info(f"Analyzing process with PID: {pid}")
            # Check if process connect to internet and is suspicious
            proc = psutil.Process(pid)
            if not proc.is_running():
                self.logger.info(f"Process {pid} is not running, skipping analysis")
                self.log_func(f"Process {pid} is not running, skipping analysis", "IGNORED")
                return is_suspicious, results
            proc_name = proc['name'].lower()

            if proc_name in self.exclusions.get('processes', []):
                self.logger.info(f"Process {proc_name}-{pid} is in exclusion list, skipping analysis")
                self.log_func(f"Process {proc_name}-{pid} is in exclusion list, skipping analysis", "IGNORED")
                return is_suspicious, results

            exe_path = proc.exe()
            if any(exe_path.lower().startswith(folder.lower()) for folder in self.analyzer.exclusions.get('folders', [])):
                #self._log(f"Skipping process in excluded folder: {exe_path} (PID: {pid})", "DEBUG")
                return is_suspicious, results
            
            cmdline =  ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else ''
           
            if cmdline and any(re.search(pattern, cmdline[0], re.IGNORECASE) for pattern in self.exclude_command_pattern_regexes):
                self.logger.info(f"Process {proc_name}-{pid} command line matches exclusion patterns, skipping analysis")
                self.log_func(f"Process {proc_name}-{pid} command line matches exclusion patterns, skipping analysis", "IGNORED")
                return is_suspicious, results

            user = proc.username()
            connections = proc.connections(kind='inet')
            conn_info_list = []
            for conn in connections:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                # conn_info = {
                #     'status': conn.status,
                #     'local_address': laddr,
                #     'remote_address': raddr,
                #     'family': socket.AddressFamily(conn.family).name,
                #     'type': socket.SocketKind(conn.type).name
                # }
                if is_ip_suspicious(raddr, conn.raddr.port):
                    is_suspicious = True
                    threat_score += self.scoring.get('suspicious_connection', 30)
                    results['suspiscious_ip'].append(raddr)
                    results['suspicious_ports'].append(conn.raddr.port)
                
                if is_ip_suspicious(conn.laddr.ip, conn.laddr.port):
                    is_suspicious = True
                    threat_score += self.scoring.get('suspicious_connection', 30)
                    results['suspiscious_ip'].append(conn.laddr.ip)
                    results['suspicious_ports'].append(conn.laddr.port)
            

                      
            self.log_func(f"Process {proc_name}-{pid} is running cmd: {cmdline}","WARN")
            if len(connections) > 0:
                for cmd in self.suspicious_commands:
                    if cmd in cmdline:
                        is_suspicious = True
                        self.log_func(f"Process {proc_name}-{pid} is running cmd: {cmd}","WARN")
                        self.logger.warn(f"Process {proc_name}-{pid} is running cmd: {cmd}")
                for arg in self.suspicious_cmd_args :
                    if arg in cmdline:
                        self.log_func(f"Process {proc_name}-{pid} is running with suspicious arg: {arg}","WARN")
                        self.logger.warn(f"Process {proc_name}-{pid} is running with suspicious arg: {arg}")
            # # Child Processes
            # child_processes = []
            # if  is_child == False:
            #     try:
            #         children = proc_info.children(recursive=True)
            #         for child in children:
            #             x = await self.analyze_process(child.pid, is_child = True)
            #             is_suspicious, results = x
            #             child_processes.append(results)
            #     except:
            #         child_processes = [{'error': 'Unable to access child processes'}]

            has_suspicious_handle, handle_output = self.check_handles(pid)
            threat_score += handle_output.get('threat_score',0)
            results.update(handle_output)
            if has_suspicious_handle:
                for handle_info in handle_output.get('suspicious_process', []):
                    self.logger.info(f"Process {pid} is accessed by suspicious process {handle_info['Process']}")
                    dlls_results , dll_score = self._analyzing_dlls(handle_info)
                    threat_score += dll_score 
                    results.update(dlls_results)

                for handle_info in handle_output.get('suspicious_system_process', []):
                    self.logger.info(f"Process {pid} is accessed by SYSTEM suspicious process {handle_info['Process']}")
                    self.log_func(f"Process {pid} is accessed by SYSTEM suspicious process {handle_info['Process']}", "CRITICAL")
                    dlls_results , dll_score = self._analyzing_dlls(handle_info)
                    threat_score += dll_score 
                    results.update(dlls_results)

            results['threat_score'] = threat_score
            #results['child_processes'] = child_processes
            return is_suspicious, results

        except Exception as e:
            self.logger.error(f"Unexpected error analyzing process {pid}: {str(e)}")
            self.log_func(f"Unexpected error analyzing process {pid}: {str(e)}", "ERROR")
            return is_suspicious, results

    async def analyze_file(self, file_path):
        """Analyze file and take appropriate actions based on threat score."""
        results ={}
        threat_score = 0
        is_suspicious = False
        try:
            if any(file_path.startswith(folder) for folder in self.exclusions['folders']):
                self.log_func(f"File {file_path} ignore due to in exclusion folder","IGNORED")
                return 
            
            # Hash to check if already checked
            file_hash = self.parser.hash_file_md5(file_path)
            if file_hash in list(self.watchlist.watchlist_file.keys()):
                self.log_func(f"File {file_path} already analyzed, skipping", "IGNORED")
                return
            
            is_valid, file_type, type_score = self.parser.validate_file_type(file_path)
            threat_score += type_score
            print(f"File type: {file_type}")
            
            if not is_valid:
                self.log_func(f"File type not Valid: {file_path} - type:{file_type}", "IGNORED")
                return

            if "office" in file_type:    
                res = await self.analyze_office(file_path)
                has_suspicious, analyze_office_results = res
                is_suspicious = has_suspicious
                results.update(analyze_office_results)
                threat_score += analyze_office_results.get('threat_score', 0)
            elif "exe" in file_type:
                res = await self.analyze_exe(file_path)
                has_suspicious, analyze_exe_results = res
                is_suspicious = has_suspicious
                results.update(analyze_exe_results)
                threat_score += analyze_exe_results.get('threat_score', 0)
            else:
                self.log_func(f"File type not supported: {file_path} - {file_type}" , "IGNORED")
                return
            
            results['threat_score'] = threat_score
            if threat_score >= 70:
                self.log_func(f"File {file_path} is dangerous (Score: {threat_score})", "CRITICAL")
                self.watchlist.add_file(file_hash, file_path, results)
            else:
                self.log_func(f"File {file_path} deemed safe (Score: {threat_score})", "INFO")
            return is_suspicious, results

        except PermissionError as e:
            return is_suspicious, results
        except FileNotFoundError as e:
            return is_suspicious, results
        except Exception as e:
            self.log_func(f"Analysis failed for {file_path}: {str(e)}", "ERROR")
            return is_suspicious, results

    def _is_encoded_payload(self, payload):
        """Check if payload appears encoded or encrypted."""
        # High proportion of non-printable characters
        non_printable = sum(1 for c in payload if ord(c) < 32 or ord(c) > 126)
        if non_printable > 5:
            return True

        #https://github.com/decalage2/oletools/blob/master/oletools/olevba.py
        # Base64
        if re.search(r'(?:[A-Za-z0-9+/]{4}){1,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)?', payload):
            return True
        # Hexadecimal
        if re.search(r'(?:[0-9A-Fa-f]{2}){4,}', payload):
            return True
        # (see https://github.com/JamesHabben/MalwareStuff)
        # dridex_string
        if re.search(r'"[0-9A-Za-z]{20,}"', payload):
            return True

        return False

    def analyze_packet(self, packet):
        """Process network packets, logging suspicious Office-related traffic."""
        
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Unknown"
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
                if packet.haslayer("Raw"):
                    payload = packet["Raw"].load.decode(errors='ignore').strip()
                    if any(x in payload.lower() for x in ["get", "post"]) and self._is_encoded_payload(payload):
                        self._log(f"Network: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}", "WARN")
                        self._log(f"Potential C2 communication detected: {payload}", "CRITICAL")
                        if src_ip not in self.analyzer.exclusions.get('ips', []):
                            self.watchlist.watchlist_ip.append(src_ip)
                        else:
                            self.watchlist.watchlist_ip.append(src_ip)
                            

        except Exception as e:
            self._log(f"Packet processing error: {str(e)}", "ERROR")