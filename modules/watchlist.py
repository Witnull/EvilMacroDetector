
from datetime import datetime
import os
import json
import sys


class Watchlist:
    """ Class to track processes actions"""
    def __init__(self, log_dir, log_func):
        self.save_dir = os.path.join(log_dir, f"watchlist_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        os.makedirs(self.save_dir, exist_ok=True)
        self.log_func = log_func
        self.file_path = os.path.join(self.save_dir, "watchlist_process.json")
        self.watchlist_process = {
            #    0000: [
            #        {
            #            "Process": "explorer.exe",
            #            "PID": 4136,
            #            "Type": "Thread",
            #            "User": "NTUX\\null",
            #            "Name": "explorer.exe",
            #            "Thread_Parent_PID": "4136",
            #            "Access": "READ_CONTROL|DELETE|SYNCHRONIZE|WRITE_DAC|WRITE_OWNER|THREAD_ALL_ACCESS"
            #            "Timestamp": 19078978978
            #        }
            #    ],
        }

        self.watchlist_file = {
            #    file.txt: [
            #        {
            #            
            #        }
            #    ],
        }
        self.summaries = {
            "file": {},  # Summary of file-related actions
            "process": {},  # Summary of process-related actions
        }
        self.watchlist_keywords =[]
        self.last_saved = datetime.now()

    def generate_summary_process(self, pid):
        summary = {
            "process": None,
            "pid": pid,
            "type": None,
            "user": None,
            "name": None,
            "thread_parent_pid": None,
            "access": None,
            "file_related": [],  # List of files related to the process that is suspicious
            "related_pid": [],  # List of related PIDs
            "actions": [],  # List of actions taken by the process
            "threat_score": 0,  # Threat score based on actions taken
            "keywords": [],
            "timestamp": None,  # Timestamp of the last update
            "other_info":[]  # Placeholder for any other information
        }

        if pid in self.watchlist_process:
            process_info = self.watchlist_process[pid]
            for entry in process_info:
                if entry:
                    if summary["process"] is None:
                        summary["process"] = entry.get("process")
                    if summary["type"] is None:
                        summary["type"] = entry.get("type")
                    if summary["user"] is None:
                        summary["user"] = entry.get("user")
                    if summary["name"] is None:
                        summary["name"] = entry.get("name")
                    if summary["thread_parent_pid"] is None:
                        summary["thread_parent_pid"] = entry.get("thread_parent_pid")
                    if summary["access"] is None:
                        summary["access"] = entry.get("access")
                    if entry.get("file_related"):
                        summary["file_related"].extend(entry.get("file_related"))
                    if entry.get("related_pid"):
                        summary["related_pid"].extend(entry.get("related_pid"))
                    if entry.get("actions"):
                        summary["actions"].extend(entry.get("actions"))
                    if entry.get("actions"):
                        summary["actions"].extend(entry.get("actions"))
                    if entry.get("threat_score"):
                        summary["threat_score"] += entry.get("threat_score", 0)
                    if entry.get("other_info"):
                        summary["other_info"].extend(entry.get("other_info"))
                    # Add timestamp to the summary
                    summary["timestamp"] = entry.get("timestamp")
        return summary

    def generate_summary_file(self, file_hash):
        summary = {
            "file": None,
            "file_path": None,
            "related_pid": [],  # List of related PIDs
            "actions": [],  # List of actions taken by the file
            "related_process": [],  # List of related processes
            "threat_score": 0,  # Threat score based on actions taken
            "timestamp": None  # Timestamp of the last update
        }

        if file_hash in self.watchlist_file:
            file_info = self.watchlist_file[file_hash]
            for entry in file_info:
                if entry:
                    if summary["file"] is None:
                        summary["file"] = entry.get("file")
                    if entry.get("file_path"):
                        summary["file_path"] = entry.get("file_path")
                    if entry.get("related_pid"):
                        summary["related_pid"].extend(entry.get("related_pid"))
                    if entry.get("actions"):
                        summary["actions"].extend(entry.get("actions"))
                    if entry.get("threat_score"):
                        summary["threat_score"] += entry.get("threat_score", 0)
                    # Add timestamp to the summary
                    summary["timestamp"] = entry.get("timestamp")
        return summary

    def add_file(self, file_hash ,file_path, info):
        """ Add a file to the watchlist 
        Args:
            file_path (str): Path to the file
            info (dict): File information
        """
        info["timestamp"] = datetime.now()
        file_name = os.path.basename(file_path)
        self.watchlist_file[file_hash] = self.watchlist_file.get(file_hash, [])
        self.watchlist_file[file_hash].append(info)
        self.log_func(f"Adding file to watchlist: {file_name} - {file_hash}", "WATCHLIST")
        self.summaries['file'][file_hash] = self.generate_summary_file(file_hash)
        self.save_to_json()

    def add_process(self, pid, info):
        """ Add a process to the watchlist 
        Args:
            pid (int): Process ID
            info (dict): Process information
        """
        info["timestamp"] = datetime.now()
        self.watchlist_process[pid] = self.watchlist_process.get(pid, [])
        self.watchlist_process[pid].append(info)
        self.summaries['process'][pid] = self.generate_summary_process(pid)
        self.save_to_json()

    def remove_process(self, pid):
        """ Remove a process from the watchlist """
        if pid in self.watchlist_process:
            del self.watchlist_process[pid]

    def get_process(self, pid):
        """ Get a process from the watchlist """
        return self.watchlist_process.get(pid, None)

    def save_to_json(self):
        """ Save the watchlist to a JSON file """
        try:
            with open(self.file_path, 'w') as f:
                json.dump(self.watchlist_process, f)
            with open(self.file_path.replace(".json", "_summary.json"), 'w') as f:
                json.dump(self.summaries, f)
            return 
        except Exception as e:
            print(f"Error saving watchlist to JSON: {e}")
            return
