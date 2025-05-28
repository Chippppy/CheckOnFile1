import os
import psutil
import threading
import time
import logging
import subprocess
from datetime import datetime

class SandboxMonitor:
    def __init__(self):
        self.monitoring = False
        self.process = None
        self.psutil_process = None
        self.log_file = None
        self.monitor_thread = None
        self.activities = []

    def start_monitoring(self, file_path):
        """
        Start monitoring a process
        """
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.log_file = f"sandbox_log_{timestamp}.txt"
            self.monitoring = True
            
            # Start the process using subprocess
            self.process = subprocess.Popen([file_path])
            # Get the psutil Process object for monitoring
            self.psutil_process = psutil.Process(self.process.pid)
            
            self.monitor_thread = threading.Thread(target=self._monitor_process)
            self.monitor_thread.start()
            return {"status": "Monitoring started", "pid": self.process.pid}
        except Exception as e:
            return {"error": f"Error starting monitoring: {str(e)}"}

    def stop_monitoring(self):
        """
        Stop monitoring and kill the process
        """
        self.monitoring = False
        if self.process:
            try:
                self.process.kill()
            except:
                pass
        if self.psutil_process:
            try:
                self.psutil_process.kill()
            except:
                pass
        if self.monitor_thread:
            self.monitor_thread.join()
        return {"status": "Monitoring stopped", "activities": self.activities}

    def _monitor_process(self):
        """
        Monitor process activities
        """
        while self.monitoring:
            try:
                # Monitor CPU and memory usage
                cpu_percent = self.psutil_process.cpu_percent()
                memory_info = self.psutil_process.memory_info()

                # Monitor file operations
                try:
                    open_files = self.psutil_process.open_files()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    open_files = []
                
                # Monitor network connections
                try:
                    connections = self.psutil_process.connections()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    connections = []

                # Monitor child processes
                try:
                    children = self.psutil_process.children(recursive=True)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    children = []

                activity = {
                    'timestamp': datetime.now().isoformat(),
                    'cpu_percent': cpu_percent,
                    'memory_usage': {
                        'rss': memory_info.rss,
                        'vms': memory_info.vms
                    },
                    'open_files': [f.path for f in open_files],
                    'connections': [
                        {
                            'local_addr': c.laddr,
                            'remote_addr': c.raddr if c.raddr else None,
                            'status': c.status
                        } for c in connections
                    ],
                    'child_processes': [
                        {
                            'pid': child.pid,
                            'name': child.name()
                        } for child in children
                    ]
                }

                self.activities.append(activity)
                self._log_activity(activity)

                time.sleep(1)  # Monitor every second

            except psutil.NoSuchProcess:
                self.monitoring = False
                break
            except Exception as e:
                self.activities.append({
                    'timestamp': datetime.now().isoformat(),
                    'error': str(e)
                })

    def _log_activity(self, activity):
        """
        Log activity to file
        """
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(f"{activity['timestamp']} - {str(activity)}\n") 