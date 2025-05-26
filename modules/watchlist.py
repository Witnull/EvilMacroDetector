from datetime import datetime
import os
import json
from queue import Queue
import sys
import trio
import asyncio
from threading import Lock, RLock
from collections import deque
import time

from datetime import datetime, timedelta
import os
import json
import trio
import re
import threading

class Watchlist:
    """Class to track process and file actions with efficient summary generation and saving."""
    def __init__(self, log_dir, log_func):
        self.save_dir = os.path.join(log_dir, f"watchlist_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(self.save_dir, exist_ok=True)
        self.log_func = log_func
        self.file_path = os.path.join(self.save_dir, "watchlist_")
        self.watchlist_process = {}
        self.watchlist_file = {}
        self.watchlist_ip={}
        self.watchlist_url={}
        self.summaries = {
            "file_name_to_hash": {},
            "file": {},
            "process": {},
        }
        self.last_saved = datetime.now()
        self.summary_proc_last_gen = {}
        self.summary_file_last_gen = {}
        self.summary_interval = timedelta(seconds=5)
        self.save_interval = timedelta(seconds=15)
        self.max_entry_age = timedelta(hours=24)  # Cleanup entries older than 24 hours
        self._save_queue = Queue(1)
        self._save_lock = trio.Lock()
        self._save_worker_started = False
      
    async def generate_summary_process(self, pid, force=False):
        """Generate a summary for a process, updating incrementally."""
        
        last_gen = self.summary_proc_last_gen.get(pid, datetime.min)
        if not force and (datetime.now() - last_gen).total_seconds() < self.summary_interval.total_seconds():
            return self.summaries["process"].get(pid)

        summary = {
            "process": None,
            "pid": pid,
            "type": None,
            "user": None,
            "name": None,
            "thread_parent_pid": None,
            "access": None,
            "file_related": [],
            "related_pid": [],
            "actions": [],
            "threat_score": 0,
            "keywords": [],
            "timestamp": datetime.now(),
            "other_info": []
        }

        if pid in self.watchlist_process:
            process_info = self.watchlist_process[pid]
            for entry in process_info:
                if not entry:
                    continue
                summary["process"] = summary["process"] or entry.get("process")
                summary["type"] = summary["type"] or entry.get("type")
                summary["user"] = summary["user"] or entry.get("user")
                summary["name"] = summary["name"] or entry.get("name")
                summary["thread_parent_pid"] = summary["thread_parent_pid"] or entry.get("thread_parent_pid")
                summary["access"] = summary["access"] or entry.get("access")
                summary["file_related"].extend(entry.get("file_related", []))
                summary["related_pid"].extend(entry.get("related_pid", []))
                summary["actions"].extend(entry.get("actions", []))  # Fixed duplicate
                summary["threat_score"] += entry.get("threat_score", 0)
                summary["other_info"].extend(entry.get("other_info", []))

        self.summaries["process"][pid] = summary
        self.summary_proc_last_gen[pid] = datetime.now()
        self.log_func(f"Generated summary for process: {pid}", "WATCHLIST")
        return summary

    async def generate_summary_file(self, file_hash, force=False):
        """Generate a summary for a file, updating incrementally."""

        last_gen = self.summary_file_last_gen.get(file_hash, datetime.min)
        if not force and (datetime.now() - last_gen).total_seconds() < self.summary_interval.total_seconds():
            return self.summaries["file"].get(file_hash)

        summary = {
            "file": None,
            "file_path": None,
            "related_pid": [],
            "actions": [],
            "related_process": [],
            "threat_score": 0,
            "timestamp": datetime.now()
        }

        if file_hash in self.watchlist_file:
            file_info = self.watchlist_file[file_hash]
            for entry in file_info:
                if not entry:
                    continue
                summary["file"] = summary["file"] or entry.get("file")
                summary["file_path"] = summary["file_path"] or entry.get("file_path")
                summary["related_pid"].extend(entry.get("related_pid", []))
                summary["actions"].extend(entry.get("actions", []))
                summary["threat_score"] += entry.get("threat_score", 0)
                summary["related_process"].extend(entry.get("related_process", []))

        self.summaries["file"][file_hash] = summary
        self.summary_file_last_gen[file_hash] = datetime.now()
        self.log_func(f"Generated summary for file: {file_hash}", "WATCHLIST")
        return summary

    async def generate_summaries(self, force=False):
        """Generate summaries for all processes and files."""

        tasks = []
        for pid in list(self.watchlist_process.keys()):
            tasks.append(self.generate_summary_process(pid, force))
        for file_hash in list(self.watchlist_file.keys()):
            tasks.append(self.generate_summary_file(file_hash, force))
        await trio.run_all(tasks)

    async def add_file(self, file_hash, file_path, info):
        """Add a file to the watchlist and update summary."""

        info["timestamp"] = datetime.now()
        file_name = os.path.basename(file_path)
        self.watchlist_file.setdefault(file_hash, []).append(info)
        self.summaries["file_name_to_hash"][file_name] = file_hash
        self.log_func(f"Added file to watchlist: {file_path} - {file_hash}", "WATCHLIST")
        await self.generate_summary_file(file_hash, force=True)
        await self.save_to_json()

    async def add_process(self, pid, info):
        """Add a process to the watchlist and update summary."""

        info["timestamp"] = datetime.now()
        self.watchlist_process.setdefault(pid, []).append(info)
        self.log_func(f"Added process to watchlist: {pid}", "WATCHLIST")
        await self.generate_summary_process(pid, force=True)
        await self.save_to_json()

    async def remove_process(self, pid):
        """Remove a process from the watchlist and its summary."""

        if pid in self.watchlist_process:
            del self.watchlist_process[pid]
            self.summaries["process"].pop(pid, None)
            self.summary_proc_last_gen.pop(pid, None)
            self.log_func(f"Removed process from watchlist: {pid}", "WATCHLIST")
            await self.save_to_json()

    async def cleanup_old_entries(self):
        """Remove entries older than max_entry_age."""

        now = datetime.now()
        for pid in list(self.watchlist_process.keys()):
            entries = self.watchlist_process[pid]
            self.watchlist_process[pid] = [
                e for e in entries if now - e.get("timestamp", now) < self.max_entry_age
            ]
            if not self.watchlist_process[pid]:
                del self.watchlist_process[pid]
                self.summaries["process"].pop(pid, None)
                self.summary_proc_last_gen.pop(pid, None)

        for file_hash in list(self.watchlist_file.keys()):
            entries = self.watchlist_file[file_hash]
            self.watchlist_file[file_hash] = [
                e for e in entries if now - e.get("timestamp", now) < self.max_entry_age
            ]
            if not self.watchlist_file[file_hash]:
                del self.watchlist_file[file_hash]
                self.summaries["file"].pop(file_hash, None)
                self.summary_file_last_gen.pop(file_hash, None)
                for fname, fhash in list(self.summaries["file_name_to_hash"].items()):
                    if fhash == file_hash:
                        del self.summaries["file_name_to_hash"][fname]

        self.log_func("Cleaned up old entries", "WATCHLIST")
        await self.save_to_json()

    async def _save_worker(self):
        while True:
            await self._save_queue.get()
            async with self._save_lock:
                await self._do_save_to_json()

    async def _do_save_to_json(self):
        try:
            async with trio.open_file(self.file_path + "process.json", "w") as f:
                await f.write(json.dumps(self.watchlist_process))
            async with trio.open_file(self.file_path + "file.json", "w") as f:
                await f.write(json.dumps(self.watchlist_file))
            async with trio.open_file(self.file_path + "summary.json", "w") as f:
                await f.write(json.dumps(self.summaries))
            self.last_saved = datetime.now()
            self.log_func(f"Watchlist saved to JSON: {self.file_path}", "WATCHLIST")
        except Exception as e:
            self.log_func(f"Error saving watchlist to JSON: {e}", "ERROR")

    async def save_to_json(self, force=False):
        if not force and (datetime.now() - self.last_saved).total_seconds() < self.save_interval.total_seconds():
            return
        # Start the save worker if not already started
        if not self._save_worker_started:
            trio.lowlevel.spawn_system_task(self._save_worker)
            self._save_worker_started = True
        await self._save_queue.put(True)

    async def compile_target_informations(self, target_info):
        """
        Compile target information from watchlist.
        Correlate process, file, and IP information to trace origin.
        Args:
            target_info: File hash, file path, PID, or IP address to analyze.
        Returns:
            Dict containing correlated information about the target.
        """

        report = {
            "target": target_info,
            "type": None,
            "file_details": [],
            "process_details": [],
            "network_details": [],
            "origin": None,
            "timestamp": datetime.now().isoformat(),
            "threat_score": 0,
            "correlations": []
        }

        # Determine target type (file hash, file path, PID, or IP)
        if target_info in self.watchlist_file or target_info in self.summaries["file_name_to_hash"].values():
            report["type"] = "file_hash"
            file_hash = target_info
        elif target_info in self.summaries["file_name_to_hash"]:
            report["type"] = "file_path"
            file_hash = self.summaries["file_name_to_hash"].get(target_info)
        elif target_info in self.watchlist_process or target_info.isdigit():
            report["type"] = "pid"
            pid = int(target_info)
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_info):
            report["type"] = "ip"
            ip = target_info
        else:
            report["type"] = "unknown"
            self.log_func(f"Unknown target type for: {target_info}", "ERROR")
            return report

        # File-based target (hash or path)
        if report["type"] in ["file_hash", "file_path"]:
            if report["type"] == "file_path":
                file_hash = self.summaries["file_name_to_hash"].get(target_info)
            if file_hash and file_hash in self.watchlist_file:
                file_summary = await self.generate_summary_file(file_hash, force=True)
                report["file_details"].append(file_summary)
                report["threat_score"] += file_summary.get("threat_score", 0)
                
                # Correlate with processes
                for pid in file_summary.get("related_pid", []):
                    if pid in self.watchlist_process:
                        proc_summary = await self.generate_summary_process(pid, force=True)
                        report["process_details"].append(proc_summary)
                        report["threat_score"] += proc_summary.get("threat_score", 0)
                        report["correlations"].append({
                            "type": "file_to_process",
                            "file_hash": file_hash,
                            "pid": pid,
                            "process_name": proc_summary.get("name")
                        })

                # Correlate with network (URLs and IPs)
                for entry in self.watchlist_file.get(file_hash, []):
                    if "source_url" in entry:
                        report["network_details"].append({
                            "url": entry["source_url"],
                            "timestamp": entry.get("timestamp").isoformat()
                        })
                        report["origin"] = entry["source_url"]
                    if "source_ip" in entry:
                        report["network_details"].append({
                            "ip": entry["source_ip"],
                            "timestamp": entry.get("timestamp").isoformat()
                        })
                        report["origin"] = entry["source_ip"] if not report["origin"] else report["origin"]

                # Check for C2 IPs in watchlist_ip
                for ip in self.watchlist_ip:
                    for entry in self.watchlist_ip[ip]:
                        if file_hash in entry.get("related_files", []):
                            report["network_details"].append({
                                "ip": ip,
                                "type": "C2",
                                "timestamp": entry.get("timestamp").isoformat()
                            })
                            report["correlations"].append({
                                "type": "file_to_c2",
                                "file_hash": file_hash,
                                "ip": ip
                            })

        # Process-based target (PID)
        elif report["type"] == "pid":
            if pid in self.watchlist_process:
                proc_summary = await self.generate_summary_process(pid, force=True)
                report["process_details"].append(proc_summary)
                report["threat_score"] += proc_summary.get("threat_score", 0)
                
                # Correlate with files
                for file_path in proc_summary.get("file_related", []):
                    file_hash = self.summaries["file_name_to_hash"].get(os.path.basename(file_path))
                    if file_hash and file_hash in self.watchlist_file:
                        file_summary = await self.generate_summary_file(file_hash, force=True)
                        report["file_details"].append(file_summary)
                        report["threat_score"] += file_summary.get("threat_score", 0)
                        report["correlations"].append({
                            "type": "process_to_file",
                            "pid": pid,
                            "file_hash": file_hash,
                            "file_path": file_path
                        })

                # Correlate with network
                for entry in self.watchlist_process.get(pid, []):
                    if "network" in entry:
                        report["network_details"].append(entry["network"])
                        report["origin"] = entry["network"].get("url") or entry["network"].get("ip")

        # IP-based target
        elif report["type"] == "ip":
            if ip in self.watchlist_ip:
                for entry in self.watchlist_ip[ip]:
                    report["network_details"].append({
                        "ip": ip,
                        "type": entry.get("type", "unknown"),
                        "timestamp": entry.get("timestamp").isoformat()
                    })
                    # Correlate with files
                    for file_hash in entry.get("related_files", []):
                        if file_hash in self.watchlist_file:
                            file_summary = await self.generate_summary_file(file_hash, force=True)
                            report["file_details"].append(file_summary)
                            report["threat_score"] += file_summary.get("threat_score", 0)
                            report["correlations"].append({
                                "type": "ip_to_file",
                                "ip": ip,
                                "file_hash": file_hash
                            })
                    # Correlate with processes
                    for pid in entry.get("related_pids", []):
                        if pid in self.watchlist_process:
                            proc_summary = await self.generate_summary_process(pid, force=True)
                            report["process_details"].append(proc_summary)
                            report["threat_score"] += proc_summary.get("threat_score", 0)
                            report["correlations"].append({
                                "type": "ip_to_process",
                                "ip": ip,
                                "pid": pid
                            })
                    if entry.get("type") == "download":
                        report["origin"] = ip

        # Save report to JSON
        report_file = os.path.join(self.save_dir, f"report_{target_info}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            async with trio.open_file(report_file, "w") as f:
                await f.write(json.dumps(report, indent=2))
            self.log_func(f"Target information report saved to: {report_file}", "WATCHLIST")
        except Exception as e:
            self.log_func(f"Error saving report: {e}", "ERROR")

        self.log_func(f"Compiled target information for: {target_info}", "WATCHLIST")
        return report