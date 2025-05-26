import json5
import logging
import os
import psutil
import re
import time

from datetime import datetime
from scapy.all import  IP, TCP, UDP
from scapy.main import load_layer
import trio
load_layer("tls")
from scapy.layers.tls.record import TLS
from queue import Queue

from modules.parser import Parser
from modules.threat_response import ThreatResponse
from uuid import uuid4



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

        
        self.parser = Parser(sysinternals_path, self.log_dir, self.blacklist, self.watchlist, self.log_func)
        self.threat_response = ThreatResponse(self.log_func, self.log_dir, self.parser)

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
        trace_id = None
        if proc_info: # is_running
            has_suspicious_dll, dll_results = self.parser.check_dlls(proc_info.pid)
            if has_suspicious_dll:
                for dll in dll_results.get('suspicious_dlls', []):
                    dll_name = os.path.basename(dll['path']).lower()
                    self.logger.info(f"Process {proc_info.pid} has suspicious DLL: {dll_name}")
                    if dll_name in self.watchlist.watchlist_file_name:
                        self.logger.info(f"Process {proc_info.pid} has suspicious DLL in watchlist: {dll_name}")
                        self.log_func(f"Process {proc_info.pid} has suspicious DLL in watchlist: {dll_name}", "CRITICAL")
                        threat_score += self.scoring.get('danger_dll', 50)
                        trace_id = self.watchlist.watchlist_file_name[dll_name].get('trace', str(uuid4()))
        return dll_results, threat_score, trace_id

    async def _analyzing_suspicious_handle(self, handle_info):
        results ={}
        threat_score = 0
        pid = handle_info['pid']
        for handle_info in self.handle_output.get('suspicious_process', []):
            self.logger.info(f"Process {pid} is accessed by suspicious process {handle_info['Process']}")
            res = await self._analyzing_dlls(handle_info['pid'])
            dlls_results , dll_score , trace_id = res
            threat_score += dll_score 
            self.parser.merge_dicts(results, dlls_results)
        return results, threat_score , trace_id

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
            'has_macros': False,
            'ioc': False,
            'vba_obfuscated': False,
            'autoexec': False
        }
        is_suspicious = False
        threat_score = 0

        try:
            self.logger.info(f"Analyzing Office file: {file_path}")

            res = await self.parser.check_macros(file_path)
            has_suspicious_macro, macro_results = res
            threat_score += macro_results.get('threat_score', 0)
            self.parser.merge_dicts(results, macro_results)

            if not has_suspicious_macro: #no macros found - normal office file
                return is_suspicious, results
            
            res = await self.parser.check_handles(file_path)
            has_suspicious_handle, handle_output = res
            threat_score += handle_output.get('threat_score', 0)
            self.parser.merge_dicts(results, handle_output)

            file_name = os.path.basename(file_path)
                # Check if any keywords match known IOCs
            for keyword in macro_results['keywords']:
                #self.log_func(f"Keyword found in macro: {keyword}", "INFO")
                if "ip@" in keyword :
                    ip = keyword.split(':')[0].strip()
                    self.log_func(f"IP found in macro: {ip} - add to watchlist", "CRITICAL")
                    self.watchlist.watchlist_ip[ip] = {"type": "IOC", "trace": str(uuid4()) }
                    self.watchlist.watchlist_file_name[file_name] = {"trace": str(uuid4()), "file_path":file_path , "type": "office" }
                elif "url@" in keyword:
                    url = (keyword.split(':')[0].strip() + keyword.split(':')[1].strip()).lower() # Due to http":"//
                    self.log_func(f"URL found in macro: {url} - add to watchlist", "CRITICAL")
                    self.watchlist.watchlist_url[url] = {"type": "IOC", "trace": str(uuid4())}
                    self.watchlist.watchlist_file_name[file_name] = {"trace": str(uuid4()), "file_path":file_path , "type": "office" }
                elif "executable@" in keyword:
                    exe = keyword.split(':')[0].strip().lower()
                    self.log_func(f"Executable found in macro: {exe} - add to watchlist", "CRITICAL")
                    self.watchlist.watchlist_file_name[exe] = {"type": "IOC", "trace": str(uuid4()) }
                    self.watchlist.watchlist_file_name[file_name] = {"trace": str(uuid4()), "file_path":file_path , "type": "office" }

            if has_suspicious_handle:
                res = await self._analyzing_suspicious_handle(handle_output)
                suspicious_handle_results, dll_score, trace_id = res
                threat_score += dll_score
                self.parser.merge_dicts(results, suspicious_handle_results)
                if trace_id:
                    results['trace'] = trace_id
                    self.watchlist.add_file(file_path, results)
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
                threat_score += self.scoring.get('unsigned_file', 30)

            # Check handles and dlls
            res = await self.parser.check_handles(file_path)
            has_suspicious_handle, handle_output = res
            threat_score += handle_output.get('threat_score', 0)
            self.parser.merge_dicts(results, handle_output)

        
            if has_suspicious_handle: # then the file is being used by some process and in watchlist
                res = await self._analyzing_suspicious_handle(handle_output)
                suspicious_handle_results, dll_score, trace_id = res
                threat_score += dll_score
                self.parser.merge_dicts(results, suspicious_handle_results)
                if trace_id:
                    results['trace'] = trace_id
                    self.watchlist.add_file(file_path, results)
  
            file_name = os.path.basename(file_path).lower()
            if file_name in  self.watchlist.watchlist_file_name:
                self.logger.info(f"EXE {file_name} is in watchlist")
                self.log_func(f"EXE {file_name} is in watchlist", "CRITICAL")
                is_suspicious = True
                threat_score += self.scoring.get('watchlist_file', 30)
                results['trace'] = self.watchlist.watchlist_file_name[file_name].get('trace', str(uuid4()))
                self.watchlist.watchlist_file_name[file_name]['file_path'] = file_path
                self.watchlist.watchlist_file_name[file_name]['type'] = "exe"
                self.watchlist.add_file(file_path, results)

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
            if threat_score >= 100:
                self.watchlist.add_file(file_path, results)
                self.threat_response.export_analysis_results(file_path, results)
                self.log_func(f"File {file_path} is dangerous (Score: {threat_score})", "CRITICAL")
                self.logger.critical(f"File {file_path} is dangerous (Score: {threat_score})")
                results['response'] = "Quarantined/Neutralized"
                self.watchlist.add_file(file_path, results)
                # if 'handle_output' in results:
                #     self.threat_response.terminate_process(results['handle_output'], "handle")
                if "office" in file_type:
                    await self.threat_response.remove_vba_macro(file_path)
                #self.threat_response.quarantine_file(file_path)
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

    def is_ip_suspicious(self, proc_name, ip, port):
        if ip in self.exclusions.get('ip', []) or port in self.exclusions.get('ports', []):
            self.logger.info(f"IP {ip} or port {port} is in exclusion list, skipping analysis")
            self.log_func(f"IP {ip} or port {port} is in exclusion list, skipping analysis", "IGNORED")
            return False
        if ip in self.suspicious_ip or port in self.suspicious_ports or ip in list(self.watchlist.watchlist_ip.keys()):
            self.log_func(f"Process {proc_name} has suspicious connection to {ip}-{port}", "CRITICAL")
            self.logger.critical(f"Process {proc_name} has suspicious connection to {ip}-{port}")
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

            if proc_name in list(self.watchlist.watchlist_file_name.keys()):
                self.log_func(f"Process {proc_name}-{pid} is in watchlist", "CRITICAL")
                threat_score += self.scoring.get('watchlist_file_name', 50)
                results['trace'] = self.watchlist.watchlist_file_name[proc_name].get('trace', str(uuid4()))
                self.watchlist.add_process(pid, results)

            cmdline =  ' '.join(proc.cmdline()) if proc.cmdline() else ''
            if cmdline and any(pattern.search(cmdline[0]) for pattern in self.exclude_command_pattern_regexes):
                self.logger.info(f"Process {proc_name}-{pid} command line matches exclusion patterns, skipping analysis")
                self.log_func(f"Process {proc_name}-{pid} command line matches exclusion patterns, skipping analysis", "IGNORED")
                return is_suspicious, results
            results['cmdline'] = cmdline

            for attr in list(self.watchlist.watchlist_url.keys()) + list(self.watchlist.watchlist_ip.keys()) + list(self.watchlist.watchlist_file_name.keys()):
                if attr in cmdline:
                    self.log_func(f"Process {proc_name}-{pid} is running cmd: {cmdline} - contains watchlisted url/ip/file: {attr}", "CRITICAL")
                    results['watchlisted_cmd'] = cmdline
                    threat_score += self.scoring.get('watchlist_cmd', 50)
                    # Set or get trace id
                    trace_id = None
                    # Check which watchlist it belongs to and set trace
                    if attr in self.watchlist.watchlist_url:
                        trace_id = self.watchlist.watchlist_url[attr].get('trace',str(uuid4()))
                    elif attr in self.watchlist.watchlist_ip:
                        trace_id = self.watchlist.watchlist_ip[attr].get('trace',str(uuid4()))
                    elif attr in self.watchlist.watchlist_file_name:
                        trace_id = self.watchlist.watchlist_file_name[attr].get('trace',str(uuid4()))
                    results['trace'] = trace_id
                    self.watchlist.add_process(pid, results)
                    break  # Only need to process the first match

            self.log_func(f"Process {proc_name}-{pid} is running cmd: {cmdline}","WARN")
            self.logger.warning(f"Process {proc_name}-{pid} is running cmd: {cmdline}")

            user = proc.username()
            if "system" in user.lower():
                self.logger.info(f"Process {proc_name}-{pid} is running as SYSTEM")
                self.log_func(f"Process {proc_name}-{pid} is running as SYSTEM","INFO")
                threat_score += self.scoring.get('system_process', 20)

            res = await self._analyzing_dlls(pid)
            dll_results, dll_score , trace_id = res
            threat_score += dll_score
            self.parser.merge_dicts(results, dll_results)

            if trace_id:
                results['trace'] = trace_id
                self.watchlist.add_process(pid, results)

            # connections = proc.net_connections(kind='inet')
            # for conn in connections:
            #     # Safely extract raddr info
            #     if conn.raddr:
            #         if isinstance(conn.raddr, tuple):
            #             r_ip, r_port = conn.raddr
            #         else:
            #             r_ip, r_port = conn.raddr.ip, conn.raddr.port
            #     else:
            #         r_ip, r_port = None, None

            #     # Similarly for laddr
            #     if conn.laddr:
            #         if isinstance(conn.laddr, tuple):
            #             l_ip, l_port = conn.laddr
            #         else:
            #             l_ip, l_port = conn.laddr.ip, conn.laddr.port
            #     else:
            #         l_ip, l_port = None, None

            #     # conn_info = {
            #     #     'status': conn.status,
            #     #     'local_address': laddr,
            #     #     'remote_address': raddr,
            #     #     'family': socket.AddressFamily(conn.family).name,
            #     #     'type': socket.SocketKind(conn.type).name
            #     # }
            #     if r_ip and self.is_ip_suspicious(proc_name,r_ip, r_port):
            #         is_suspicious = True
            #         threat_score += self.scoring.get('suspicious_connection', 30)
            #         results['suspiscious_ip'].append(r_ip)
            #         results['suspicious_ports'].append(r_port)

            #     if l_ip and self.is_ip_suspicious(proc_name,l_ip, l_port):
            #         is_suspicious = True
            #         threat_score += self.scoring.get('suspicious_connection', 30)
            #         results['suspiscious_ip'].append(l_ip)
            #         results['suspicious_ports'].append(l_port)
            
                      
            
            # if len(connections) > 0:
            #     for cmd in self.suspicious_commands:
            #         if cmd in cmdline:
            #             is_suspicious = True
            #             self.log_func(f"Process {proc_name}-{pid} is running cmd: {cmd}","WARN")
            #             self.logger.warning(f"Process {proc_name}-{pid} is running cmd: {cmd}")
            #             results['suspicious_commands'].append(cmd)
            #             threat_score += self.scoring.get('suspicious_commands', 10)

            #     for arg in self.suspicious_cmd_args :
            #         if arg in cmdline:
            #             self.log_func(f"Process {proc_name}-{pid} is running with suspicious arg: {arg}","WARN")
            #             self.logger.warn(f"Process {proc_name}-{pid} is running with suspicious arg: {arg}")
            #             results['suspicious_cmd_args'].append(arg)
            #             threat_score += self.scoring.get('suspicious_cmd_args', 20)

            # # Child Processes
            # child_processes = []
            # if not is_child:
            #     try:
            #         children = proc.children(recursive=True)
            #         async with trio.open_nursery() as nursery:
            #             results_list = []
            #             for child in children:
            #                 nursery.start_soon(
            #                     lambda c=child: results_list.append(self.analyze_process(c.pid, is_child=True))
            #                 )
            #         # Now results_list contains all child results
            #     except Exception:
            #         child_processes = [{'error': 'Unable to access child processes'}]

            
            # res= await self.parser.check_handles(pid)
            # has_suspicious_handle, handle_output  = res
            # threat_score += handle_output.get('threat_score',0)
            # self.parser.merge_dicts(results, handle_output)
            # if has_suspicious_handle:
            #     res = await self._analyzing_suspicious_handle(handle_output)
            #     suspicious_handle_results, dll_score = res
            #     threat_score += dll_score
            #     self.parser.merge_dicts(results, suspicious_handle_results)

            if threat_score >= 50:
                is_suspicious = True
                self.threat_response.export_analysis_results(proc_name, results)
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
                        if any( url in payload.strip() for url in list(self.watchlist.watchlist_url.keys())):
                            self.log_func(f"Packet contains watchlisted url: {payload.strip()[:100]}", "CRITICAL")
                        
                        is_encoded = self._is_encoded_payload(payload.strip())
                        self.log_func(f"Packet encoded: {is_encoded}", "NET")
                        if is_encoded:
                            self.log_func(f"Network: {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}", "NET")
                            self.log_func(f"Potential C2 communication detected: {payload.strip()[:100]}", "WARN")
                            if src_ip not in self.exclusions.get('ips', []) and src_ip in list(self.watchlist.watchlist_ip.keys()):
                                self.log_func(f"C2 communication detected from watchlisted IP: {src_ip}", "CRITICAL")
                                self.threat_response.block_ip(src_ip)
                                self.threat_response.export_analysis_results(src_ip, {"payload": payload,"src_ip": src_ip, "port": src_port, "type": "Potential C2"})
                                #self.watchlist.compile_target_informations({"val": src_ip, "type": "ip"})
                                trio.run(self.trace_backing, self.watchlist.watchlist_ip[src_ip].get('trace', 'unknown'))
                            elif dst_ip not in self.exclusions.get('ips', []) and dst_ip in list(self.watchlist.watchlist_ip.keys()):
                                self.log_func(f"C2 communication detected to watchlisted IP: {dst_ip}", "CRITICAL")
                                self.threat_response.block_ip(dst_ip)
                                self.threat_response.export_analysis_results(dst_ip, {"payload": payload,"dst_ip": dst_ip, "port": dst_port, "type": "Potential C2"})
                                #self.watchlist.compile_target_informations({"val": dst_ip, "type": "ip"})
                                trio.run(self.trace_backing, self.watchlist.watchlist_ip[dst_ip].get('trace', 'unknown'))
            
            self.log_func("Function analyze_packet completed in {:.3f} seconds".format(time.time() - benchmark_start), "BM")
        except Exception as e:
            self.log_func(f"Packet processing error: {str(e)}", "ERROR")


    async def trace_backing(self, trace_id):
        """Trace back the origin of a suspicious file or process."""
        try:
            if trace_id == 'unknown':
                self.log_func("Traceback ID is unknown, skipping traceback", "INFO")
                return
            self.log_func(f"Starting traceback for IP: {trace_id}", "TRACE")
            for ip, info in self.watchlist.watchlist_ip.items():
                if info.get('trace') == trace_id:
                    self.log_func(f"Tracing back IP {ip} with trace ID {trace_id}: {info} -> BLOCK", "TRACE")
                    self.threat_response.block_ip(ip)
                    
            self.log_func(f"Starting traceback file: {trace_id}", "TRACE")
            for file_name, info in self.watchlist.watchlist_file_name.items():
                self.log_func(f"Tracing back file {file_name} with trace ID {trace_id}: {info}", "TRACE")
                if info.get('trace') == trace_id:
                    self.log_func(f"Tracing back file {file_name} with trace ID {trace_id}: {info} -> BLOCK", "TRACE")
                    file_path = info.get('file_path', '')
                    if file_path:
                        self.threat_response.quarantine_file(file_path)
                    type_ = info.get('type', 'unknown')
                    if type_ == 'office':
                        await self.threat_response.remove_vba_macro(file_path)

            self.log_func(f"Starting traceback for process ID: {trace_id}", "TRACE")
            for process_id, info in self.watchlist.watchlist_process.items():
                self.log_func(f"Tracing back process {process_id} with trace ID {trace_id}: {info}", "TRACE")
                if info.get('trace') == trace_id:
                    self.log_func(f"Tracing back process {process_id} with trace ID {trace_id}: {info} -> BLOCK", "TRACE")
                    self.threat_response.terminate_process(process_id, "pid")

            self.log_func(f"Traceback for trace ID {trace_id} completed", "TRACE")
        except Exception as e:
            self.log_func(f"Traceback error for trace ID {trace_id}: {str(e)}", "ERROR")
            self.logger.error(f"Traceback error for trace ID {trace_id}: {str(e)}")