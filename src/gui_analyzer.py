import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import json
import threading
import os
from datetime import datetime
from analyzer.hash_analyzer import HashAnalyzer
from analyzer.pe_analyzer import PEAnalyzer
from analyzer.vt_analyzer import VTAnalyzer
from analyzer.sandbox_monitor import SandboxMonitor
from analyzer.document_analyzer import DocumentAnalyzer

class FileAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Analyzer Tool")
        self.root.geometry("800x600")
        
        # Variables
        self.file_path = tk.StringVar()
        self.sandbox_monitor = None
        self.monitoring = False
        self.current_results = {}  # Store current analysis results
        
        self._create_widgets()
        self._create_layout()

    def _create_widgets(self):
        # File selection
        self.file_frame = ttk.LabelFrame(self.root, text="File Selection", padding="5")
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path, width=90)
        self.browse_button = ttk.Button(self.file_frame, text="Browse", command=self._browse_file)

        # Analysis options
        self.options_frame = ttk.LabelFrame(self.root, text="Analysis Options", padding="5")
        self.sandbox_var = tk.BooleanVar()
        self.sandbox_check = ttk.Checkbutton(self.options_frame, text="Enable Sandbox Monitoring",
                                           variable=self.sandbox_var)

        # Control buttons
        self.control_frame = ttk.Frame(self.root, padding="5")
        self.analyze_button = ttk.Button(self.control_frame, text="Analyze",
                                       command=self._start_analysis)
        self.stop_button = ttk.Button(self.control_frame, text="Stop Monitoring",
                                    command=self._stop_monitoring, state='disabled')
        self.save_button = ttk.Button(self.control_frame, text="Save Results",
                                    command=self._save_results, state='disabled')

        # Results area
        self.results_frame = ttk.LabelFrame(self.root, text="Analysis Results", padding="5")
        self.results_text = scrolledtext.ScrolledText(self.results_frame, width=80, height=20)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var, maximum=100)

    def _create_layout(self):
        # File selection layout
        self.file_frame.pack(fill='x', padx=5, pady=5)
        self.file_entry.pack(side='left', padx=10)
        self.browse_button.pack(side='left', padx=5)

        # Options layout
        self.options_frame.pack(fill='x', padx=5, pady=5)
        self.sandbox_check.pack(side='left', padx=5)

        # Control buttons layout
        self.control_frame.pack(fill='x', padx=5, pady=5)
        self.analyze_button.pack(side='left', padx=5)
        self.stop_button.pack(side='left', padx=5)
        self.save_button.pack(side='left', padx=5)

        # Progress bar layout
        self.progress_bar.pack(fill='x', padx=5, pady=5)

        # Results layout
        self.results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)

    def _browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def _update_progress(self, value):
        self.progress_var.set(value)
        self.root.update_idletasks()

    def _update_results(self, text):
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END)

    def _save_results(self):
        """Save analysis results to a file"""
        if not self.current_results:
            messagebox.showwarning("No Results", "No analysis results available to save.")
            return

        # Get current timestamp for default filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"analysis_results_{timestamp}.log"

        # Open file dialog for saving
        file_path = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile=default_filename,
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )

        if file_path:
            try:
                with open(file_path, 'w') as f:
                    # Write timestamp and analyzed file info
                    f.write(f"Analysis Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Analyzed File: {self.file_path.get()}\n")
                    f.write("-" * 80 + "\n\n")
                    
                    # Write the results
                    json.dump(self.current_results, f, indent=4)
                
                messagebox.showinfo("Success", f"Results saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save results: {str(e)}")

    def _start_analysis(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file to analyze")
            return

        self.results_text.delete(1.0, tk.END)
        self.analyze_button.config(state='disabled')
        self.save_button.config(state='disabled')
        self.current_results = {}  # Clear previous results
        threading.Thread(target=self._run_analysis, daemon=True).start()

    def _stop_monitoring(self):
        if self.sandbox_monitor and self.monitoring:
            self.monitoring = False
            results = self.sandbox_monitor.stop_monitoring()
            self._update_results("\nSandbox Monitoring Results:")
            self._update_results(json.dumps(results, indent=4))
            self.stop_button.config(state='disabled')
            self.analyze_button.config(state='normal')
            self.save_button.config(state='normal')
            self.sandbox_monitor = None
            # Update current results with sandbox data
            self.current_results['sandbox_monitoring'] = results

    def _run_analysis(self):
        try:
            file_path = self.file_path.get()
            self.current_results = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path)
            }

            # Calculate hashes
            self._update_results("Calculating file hashes...")
            self._update_progress(20)
            hash_analyzer = HashAnalyzer()
            self.current_results['hashes'] = hash_analyzer.calculate_hashes(file_path)
            self._update_results(json.dumps(self.current_results['hashes'], indent=4))

            # VirusTotal analysis
            self._update_results("\nScanning with VirusTotal...")
            self._update_progress(40)
            try:
                vt_analyzer = VTAnalyzer()
                vt_results = vt_analyzer.scan_file(file_path)
                if 'error' not in vt_results:
                    self.current_results['virustotal'] = vt_analyzer.get_file_report(
                        self.current_results['hashes']['sha256']
                    )
                else:
                    self.current_results['virustotal'] = vt_results
                self._update_results(json.dumps(self.current_results['virustotal'], indent=4))
            except Exception as e:
                self._update_results(f"VirusTotal analysis error: {str(e)}")

            # Document analysis
            self._update_results("\nAnalyzing document properties...")
            self._update_progress(60)
            doc_analyzer = DocumentAnalyzer()
            self.current_results['document_analysis'] = doc_analyzer.analyze_file(file_path)
            self._update_results(json.dumps(self.current_results['document_analysis'], indent=4))

            # PE analysis if applicable
            if file_path.lower().endswith(('.exe', '.dll', '.sys')):
                self._update_results("\nPerforming PE analysis...")
                self._update_progress(80)
                pe_analyzer = PEAnalyzer()
                self.current_results['pe_analysis'] = pe_analyzer.analyze_pe(file_path)
                self._update_results(json.dumps(self.current_results['pe_analysis'], indent=4))

                # Sandbox monitoring if enabled
                if self.sandbox_var.get():
                    self._update_results("\nStarting sandbox monitoring...")
                    self.sandbox_monitor = SandboxMonitor()
                    monitor_results = self.sandbox_monitor.start_monitoring(file_path)
                    
                    if 'error' not in monitor_results:
                        self.monitoring = True
                        self.stop_button.config(state='normal')
                        self._update_results("Monitoring started. Click 'Stop Monitoring' to end.")
                    else:
                        self._update_results(json.dumps(monitor_results, indent=4))
                        self.current_results['sandbox_monitoring'] = monitor_results

            self._update_progress(100)

        except Exception as e:
            self._update_results(f"\nError during analysis: {str(e)}")
        finally:
            if not self.monitoring:
                self.analyze_button.config(state='normal')
                self.save_button.config(state='normal')  # Enable save button after analysis

def main():
    root = tk.Tk()
    app = FileAnalyzerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main() 