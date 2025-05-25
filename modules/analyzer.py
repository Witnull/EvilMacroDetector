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
from queue import Queue
import threading
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
        self.task_queue = Queue()  # Queue for async tasks
      

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

    async def _analyzing_dlls(self, pid):
        proc_info = psutil.Process(pid)
        threat_score = 0
        dll_results ={}
        if proc_info:
            has_suspicious_dll, dll_results = self.parser.check_dlls(proc_info.pid)
            if has_suspicious_dll:
                for dll in dll_results.get('suspicious_dlls', []):
                    self.watchlist.add_process(proc_info.pid, dll)
                    has_suspicious_dll, dll_results = self.analyze_process(dll['pid'], is_child=True)  # Analyze the process accessing the DLL
                    self.logger.info(f"Sus process {proc_info.pid} is accessing suspicious DLL: {dll['path']}")
                    self.log_func(f"Sus process {proc_info.pid} is accessing suspicious DLL: {dll['path']}", "CRITICAL")
                    threat_score += self.scoring.get('suspicious_dll_with_suspicious_processs', 40) 

        return dll_results, threat_score

    async def _analyzing_suspicious_handle(handle_info):
        results ={}
        threat_score = 0
        for handle_info in handle_output.get('suspicious_process', []):
            self.logger.info(f"Process {pid} is accessed by suspicious process {handle_info['Process']}")
            dlls_results , dll_score = await self._analyzing_dlls(handle_info['pid'])
            threat_score += dll_score 
            self.parser.merge_dicts(results, dlls_results)

        for handle_info in handle_output.get('suspicious_system_process', []):
            self.logger.info(f"Process {pid} is accessed by SYSTEM suspicious process {handle_info['Process']}")
            self.log_func(f"Process {pid} is accessed by SYSTEM suspicious process {handle_info['Process']}", "CRITICAL")
            dlls_results , dll_score = await self._analyzing_dlls(handle_info['pid'])
            threat_score += dll_score 
            self.parser.merge_dicts(results, dlls_results)
        return results, threat_score

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
        benchmark_start = time.time()
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
            # is_valid, file_type, type_score = self.parser.validate_file_type(file_path)
            # threat_score += type_score
            # if not is_valid:
            #     self.logger.info(f"Invalid file type for {file_path}: {file_type}")
            #     self.log_func(f"Invalid file type for {file_path}: {file_type}", "ERROR")
            #     return is_suspicious, results

            self.logger.info(f"Analyzing Office file: {file_path}")

            has_suspicious_macro, macro_results = self.parser.check_macros(file_path)
            threat_score += macro_results.get('threat_score', 0)
            self.parser.merge_dicts(results, macro_results)

            res = self.parser.check_handles(file_path)
            has_suspicious_handle, handle_output = res
            threat_score += handle_output.get('threat_score', 0)
            self.parser.merge_dicts(results, handle_output)

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
            self.parser.merge_dicts(results, dll_results)
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
                if has_suspicious_handle:
                    res = self._analyzing_suspicious_handle(handle_output)
                    suspicious_handle_results, dll_score = res
                    threat_score += dll_score
                    self.parser.merge_dicts(results, suspicious_handle_results)
                #########
            results['threat_score'] = threat_score     # if suspicious / mostly will > 70      
            self.log_func("Function analyze_office completed in {:.3f} seconds".format(time.time() - benchmark_start), "BM")
            
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
        benchmark_start = time.time()
        results = {
            'sigcheck': False,
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
            # is_valid, file_type, type_score = self.parser.validate_file_type(file_path)
            # threat_score += type_score
            # if not is_valid:
            #     self.logger.info(f"Invalid file type for {file_path}: {file_type}")
            #     self.log_func(f"Invalid file type for {file_path}: {file_type}", "ERROR")
            #     return is_suspicious ,results

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
            res = await self.parser.check_handles(file_path)
            has_suspicious_handle, handle_output = res
            threat_score += handle_output.get('threat_score', 0)
            self.parser.merge_dicts(results, handle_output)

            if has_suspicious_handle: # then the file is being used by some process and in watchlist
                res = self._analyzing_suspicious_handle(handle_output)
                suspicious_handle_results, dll_score = res
                threat_score += dll_score
                self.parser.merge_dicts(results, suspicious_handle_results)
            # Check Sysmon events
            # has_sysmon_event, sysmon_output = self.parser.check_sysmon_events(file_path)
            # results['sysmon'] = sysmon_output
            # if has_sysmon_event:
            #     self.logger.warning(f"Sysmon event detected for {file_path}")
            #     is_suspicious = True
            #     threat_score += self.scoring.get('sysmon_event_exe', 10)

            self.log_func("Function analyze_exe completed in {:.3f} seconds".format(time.time() - benchmark_start), "BM")
            results['threat_score'] = threat_score
            return is_suspicious, results

        except Exception as e:
            self.logger.error(f"Unexpected error analyzing EXE {file_path}: {str(e)}")
            self.log_func(f"Unexpected error analyzing EXE {file_path}: {str(e)}", "ERROR")
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

            file_ext = os.path.splitext(file_path.lower())[1].lstrip('.')
            if file_ext in self.exclusions.get('file_extensions', []):
                self.log_func(f"File {file_path} is in the exclusion list for file extensions.", "IGNORED")
                return False, 'excluded', self.scoring.get('excluded', 0)

            # Hash to check if already checked
            file_hash = await self.parser.hash_file_md5(file_path)
            if file_hash in list(self.watchlist.watchlist_file.keys()):
                self.log_func(f"File {file_path} already analyzed, skipping", "IGNORED")
                return

            is_valid, file_type, type_score  = self.parser.validate_file_type(file_path)
            threat_score += type_score
            print(f"File type: {file_type}")
            
            if not is_valid:
                self.log_func(f"File type not Valid: {file_path} - type:{file_type}", "IGNORED")
                return

            if "office" in file_type:    
                res = await self.analyze_office(file_path)
                has_suspicious, analyze_office_results = res
                is_suspicious = has_suspicious
                self.parser.merge_dicts(results, analyze_office_results)
                threat_score += analyze_office_results.get('threat_score', 0)
                if "mismatch" in file_type and is_suspicious:
                    threat_score += self.scoring.get('mismatch_office', 20)
            elif "exe" in file_type:
                res = await self.analyze_exe(file_path)
                has_suspicious, analyze_exe_results = res
                is_suspicious = has_suspicious
                self.parser.merge_dicts(results, analyze_exe_results)
                threat_score += analyze_exe_results.get('threat_score', 0)
                if "mismatch" in file_type and is_suspicious:
                    threat_score += self.scoring.get('mismatch_exe', 20)
            else:
                self.log_func(f"File type not supported: {file_path} - {file_type}" , "IGNORED")
                return
            
            results['threat_score'] = threat_score
            if threat_score >= 70:
                self.log_func(f"File {file_path} is suspicious (Score: {threat_score})", "CRITICAL")
                self.logger.warn(f"File {file_path} is suspicious (Score: {threat_score})")
                results['response'] = "Monitored"
                self.watchlist.add_file(file_hash, file_path, results)
                self.threat_response.export_analysis_results(file_path, results)
                if threat_score >= 200:    
                    self.log_func(f"File {file_path} is dangerous (Score: {threat_score})", "CRITICAL")
                    self.logger.critical(f"File {file_path} is dangerous (Score: {threat_score})")
                    results['response'] = "Quarantined/Neutralized"
                    self.watchlist.add_file(file_hash, file_path, results)
                    if results.has_key('handle_output') and results['handle_output']:
                        self.threat_response.terminate_process(results['handle_output'], "handle")
                        if file_type == "office":
                            self.threat_response.remove_vba_macro(file_path)
                        self.threat_response.quarantine_file(file_path)

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

    def is_ip_suspicious(self, ip, port):
        if ip in self.exclusions.get('ip', []) or port in self.exclusions.get('ports', []):
            self.logger.info(f"IP {ip} or port {port} is in exclusion list, skipping analysis")
            self.log_func(f"IP {ip} or port {port} is in exclusion list, skipping analysis", "IGNORED")
            return False
        if ip in self.suspicious_ip or port in self.suspicious_ports or ip in list(self.watchlist.watchlist_ip.keys()):
            self.log_func(f"Process {proc_name}-{pid} has suspicious connection to {raddr} on port {conn.raddr.port}", "CRITICAL")
            self.logger.critical(f"Process {proc_name}-{pid} has suspicious connection to {raddr} on port {conn.raddr.port}")
            return True
        return False

    async def analyze_process(self, pid, is_child=False):
        """Analyze a process for suspicious behavior."""
        benchmark_start = time.time()
        results = {
            'suspiscious_ip': [],
            'suspicious_ports': [],
            'connect_to_inet':[],
            'suspicious_commands': [],
            'suspicious_cmd_args':[],
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

            results['pid'] = pid

            proc_name = proc.name().lower()
            if proc_name in self.exclusions.get('processes', []):
                self.logger.info(f"Process {proc_name}-{pid} is in exclusion list, skipping analysis")
                self.log_func(f"Process {proc_name}-{pid} is in exclusion list, skipping analysis", "IGNORED")
                return is_suspicious, results
            results['process_name'] = proc_name


            exe_path = proc.exe()
            if any(exe_path.lower().startswith(folder.lower()) for folder in self.exclusions.get('folders', [])):
                #self._log(f"Skipping process in excluded folder: {exe_path} (PID: {pid})", "DEBUG")
                return is_suspicious, results
            results['exe_path'] = exe_path

            cmdline =  ' '.join(proc.cmdline()) if proc.cmdline() else ''
            if cmdline and any(pattern.search(cmdline[0]) for pattern in self.exclude_command_pattern_regexes):
                self.logger.info(f"Process {proc_name}-{pid} command line matches exclusion patterns, skipping analysis")
                self.log_func(f"Process {proc_name}-{pid} command line matches exclusion patterns, skipping analysis", "IGNORED")
                return is_suspicious, results
            results['cmdline'] = cmdline

            user = proc.username()
            connections = proc.connections(kind='inet')
            conn_info_list = []
            for conn in connections:
                # Safely extract raddr info
                if conn.raddr:
                    if isinstance(conn.raddr, tuple):
                        r_ip, r_port = conn.raddr
                    else:
                        r_ip, r_port = conn.raddr.ip, conn.raddr.port
                    raddr = f"{r_ip}:{r_port}"
                else:
                    raddr = "N/A"
                    r_ip, r_port = None, None

                # Similarly for laddr
                if conn.laddr:
                    if isinstance(conn.laddr, tuple):
                        l_ip, l_port = conn.laddr
                    else:
                        l_ip, l_port = conn.laddr.ip, conn.laddr.port
                    laddr = f"{l_ip}:{l_port}"
                else:
                    laddr = "N/A"
                    l_ip, l_port = None, None

                # conn_info = {
                #     'status': conn.status,
                #     'local_address': laddr,
                #     'remote_address': raddr,
                #     'family': socket.AddressFamily(conn.family).name,
                #     'type': socket.SocketKind(conn.type).name
                # }
                if r_ip and self.is_ip_suspicious(r_ip, r_port):
                    is_suspicious = True
                    threat_score += self.scoring.get('suspicious_connection', 30)
                    results['suspiscious_ip'].append(r_ip)
                    results['suspicious_ports'].append(r_port)

                if l_ip and self.is_ip_suspicious(l_ip, l_port):
                    is_suspicious = True
                    threat_score += self.scoring.get('suspicious_connection', 30)
                    results['suspiscious_ip'].append(l_ip)
                    results['suspicious_ports'].append(l_port)
            
                      
            self.log_func(f"Process {proc_name}-{pid} is running cmd: {cmdline}","WARN")
            if len(connections) > 0:
                for cmd in self.suspicious_commands:
                    if cmd in cmdline:
                        is_suspicious = True
                        self.log_func(f"Process {proc_name}-{pid} is running cmd: {cmd}","WARN")
                        self.logger.warn(f"Process {proc_name}-{pid} is running cmd: {cmd}")
                        results['suspicious_commands'].append(cmd)
                        threat_score += self.scoring.get('suspicious_commands', 10)

                for arg in self.suspicious_cmd_args :
                    if arg in cmdline:
                        self.log_func(f"Process {proc_name}-{pid} is running with suspicious arg: {arg}","WARN")
                        self.logger.warn(f"Process {proc_name}-{pid} is running with suspicious arg: {arg}")
                        results['suspicious_cmd_args'].append(arg)
                        threat_score += self.scoring.get('suspicious_cmd_args', 20)

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

            if  is_child == False:
                res= await self.parser.check_handles(pid)
                has_suspicious_handle, handle_output  = res
                threat_score += handle_output.get('threat_score',0)
                self.parser.merge_dicts(results, handle_output)
                if has_suspicious_handle:
                    res = self._analyzing_suspicious_handle(handle_output)
                    suspicious_handle_results, dll_score = res
                    threat_score += dll_score
                    self.parser.merge_dicts(results, suspicious_handle_results)

            if threat_score >= 70:
                is_suspicious = True
                self.log_func(f"Process {proc_name}-{pid} is suspicious (Score: {threat_score})", "CRITICAL")
                self.logger.critical(f"Process {proc_name}-{pid} is suspicious (Score: {threat_score})")
                results['response'] = "Monitored"
                self.watchlist.add_process(pid, results)
            else:
                self.log_func(f"Process {proc_name}-{pid} deemed safe (Score: {threat_score})", "INFO")
                self.logger.info(f"Process {proc_name}-{pid} deemed safe (Score: {threat_score})")

            self.log_func("Function analyze_process completed in {:.3f} seconds".format(time.time() - benchmark_start), "BM")
            results['threat_score'] = threat_score
            return is_suspicious, results

        except Exception as e:
            self.logger.error(f"Unexpected error analyzing process {pid}: {str(e)}")
            self.log_func(f"Unexpected error analyzing process {pid}: {str(e)}", "ERROR")
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

    def _extract_url(self, payload):
        url_match = re.search(r"(?:GET|POST)\s+([^\s]+)\s+HTTP", payload)
        return url_match.group(1) if url_match else None

    # def _start_background_trio(self):
    #         """Run a Trio event loop in a separate thread to process async tasks."""
    #         def trio_worker():
    #             async def process_tasks():
    #                 while True:
    #                     try:
    #                         dst_ip = self.task_queue.get_nowait()
    #                         report = await self.watchlist.compile_target_informations({"ip": dst_ip})
    #                         self._log(f"Compiled report for IP {dst_ip}: {report}", "INFO")
    #                     except Queue.Empty:
    #                         await trio.sleep(0.1)
    #                     except Exception as e:
    #                         self._log(f"Error in background task: {e}", "ERROR")

    #             trio.run(process_tasks)

    #         threading.Thread(target=trio_worker, daemon=True).start()

    def analyze_packet(self, packet):
        """Process network packets, logging suspicious Office-related traffic."""
        benchmark_start = time.time()
        try:

            if IP in packet:
               
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Unknown"
                src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
                if packet.haslayer("Raw"):
                    payload = packet["Raw"].load.decode(errors='ignore')
                    if any(x in payload.lower() for x in ["get", "post","user-agent"]):
                        self.log_func(f"Processing packet: {packet.summary()}", "NET")

                        if any(ext in payload.lower() for ext in self.exe_extensions + self.office_extensions):
                            self._log(f"Potential file download: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Payload: {payload[:70]}", "WARN")
                            # Extract URL if present
                            url = self._extract_url(payload)
                            if url:
                                self._log(f"Download URL: {url}", "WARN")
                                self.watchlist.watchlist_url[url] = {
                                    "type": "Potential File Download",
                                    "payload": payload,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "response": "Monitored"
                                }
                        self.log_func(f"Packet encoded: {self._is_encoded_payload(payload.strip())}", "NET")
                        if self._is_encoded_payload(payload.strip()):
                            self._log(f"Network: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}", "WARN")
                            self._log(f"Potential C2 communication detected: {payload[:70]}", "CRITICAL")
                            if src_ip not in self.exclusions.get('ips', []):
                                self.watchlist.watchlist_ip[src_ip] = {
                                    "type": "Potential C2", 
                                    "payload": payload, 
                                    "port": src_port,
                                    "response": "Blocked"
                                    }
                                self.threat_response.block_ip(src_ip)
                                #self.watchlist.compile_target_informations({"ip": src_ip})

                            else:
                                self.watchlist.watchlist_ip[dst_ip] = {
                                    "type": "Potential C2", 
                                    "payload": payload, 
                                    "port": dst_port,
                                    "response": "Blocked"
                                }
                                self.threat_response.block_ip(dst_ip)
                                #self.watchlist.compile_target_informations({"ip": dst_ip})


            self.log_func("Function analyze_packet completed in {:.3f} seconds".format(time.time() - benchmark_start), "BM")
        except Exception as e:
            self._log(f"Packet processing error: {str(e)}", "ERROR")

    
