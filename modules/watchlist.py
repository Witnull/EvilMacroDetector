from datetime import datetime
import os
import json
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

class Watchlist:
    """Class to track process and file actions with efficient summary generation and saving."""
    def __init__(self, log_dir, log_func):
        self.save_dir = os.path.join(log_dir, f"watchlist_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(self.save_dir, exist_ok=True)
        self.log_func = log_func
        self.file_path = os.path.join(self.save_dir, "watchlist_")
        self.watchlist_process = {}
        self.watchlist_file = {}
        self.watchlist_ip=[]
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
        self.lock = trio.Lock()  # For thread-safe updates

    async def generate_summary_process(self, pid, force=False):
        """Generate a summary for a process, updating incrementally."""
        async with self.lock:
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
        async with self.lock:
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
        async with self.lock:
            tasks = []
            for pid in list(self.watchlist_process.keys()):
                tasks.append(self.generate_summary_process(pid, force))
            for file_hash in list(self.watchlist_file.keys()):
                tasks.append(self.generate_summary_file(file_hash, force))
            await trio.run_all(tasks)

    async def add_file(self, file_hash, file_path, info):
        """Add a file to the watchlist and update summary."""
        async with self.lock:
            info["timestamp"] = datetime.now()
            file_name = os.path.basename(file_path)
            self.watchlist_file.setdefault(file_hash, []).append(info)
            self.summaries["file_name_to_hash"][file_name] = file_hash
            self.log_func(f"Added file to watchlist: {file_path} - {file_hash}", "WATCHLIST")
            await self.generate_summary_file(file_hash, force=True)
            await self.save_to_json()

    async def add_process(self, pid, info):
        """Add a process to the watchlist and update summary."""
        async with self.lock:
            info["timestamp"] = datetime.now()
            self.watchlist_process.setdefault(pid, []).append(info)
            self.log_func(f"Added process to watchlist: {pid}", "WATCHLIST")
            await self.generate_summary_process(pid, force=True)
            await self.save_to_json()

    async def remove_process(self, pid):
        """Remove a process from the watchlist and its summary."""
        async with self.lock:
            if pid in self.watchlist_process:
                del self.watchlist_process[pid]
                self.summaries["process"].pop(pid, None)
                self.summary_proc_last_gen.pop(pid, None)
                self.log_func(f"Removed process from watchlist: {pid}", "WATCHLIST")
                await self.save_to_json()

    async def cleanup_old_entries(self):
        """Remove entries older than max_entry_age."""
        async with self.lock:
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

    async def save_to_json(self, force=False):
        """Save watchlist and summaries to JSON files asynchronously."""
        async with self.lock:
            if not force and (datetime.now() - self.last_saved).total_seconds() < self.save_interval.total_seconds():
                return
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

    def is_file_in_watchlist(self, file_hash):
        """Check if a file is in the watchlist"""
        with self.file_lock:
            if file_hash in self.watchlist_file:
                return True
        return False