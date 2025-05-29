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
        self.hash_input = tk.StringVar()
        self.sandbox_monitor = None
        self.monitoring = False
        self.current_results = {}
        
        self._create_widgets()
        self._create_layout()

    def _create_widgets(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        
        # Create tabs
        self.file_tab = ttk.Frame(self.notebook)
        self.hash_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.file_tab, text='File Analysis')
        self.notebook.add(self.hash_tab, text='Hash Lookup')

        # File Analysis Tab
        self._create_file_analysis_widgets()
        
        # Hash Lookup Tab
        self._create_hash_lookup_widgets()

    def _create_file_analysis_widgets(self):
        # File selection
        self.file_frame = ttk.LabelFrame(self.file_tab, text="File Selection", padding="5")
        self.file_entry = ttk.Entry(self.file_frame, textvariable=self.file_path, width=90)
        self.browse_button = ttk.Button(self.file_frame, text="Browse", command=self._browse_file)

        # Analysis options
        self.options_frame = ttk.LabelFrame(self.file_tab, text="Analysis Options", padding="5")
        self.sandbox_var = tk.BooleanVar()
        self.sandbox_check = ttk.Checkbutton(self.options_frame, text="Enable Sandbox Monitoring",
                                           variable=self.sandbox_var)

        # Control buttons
        self.control_frame = ttk.Frame(self.file_tab, padding="5")
        self.analyze_button = ttk.Button(self.control_frame, text="Analyze",
                                       command=self._start_analysis)
        self.stop_button = ttk.Button(self.control_frame, text="Stop Monitoring",
                                    command=self._stop_monitoring, state='disabled')
        self.save_button = ttk.Button(self.control_frame, text="Save Results",
                                    command=self._save_results, state='disabled')

        # Results area
        self.results_frame = ttk.LabelFrame(self.file_tab, text="Analysis Results", padding="5")
        self.results_text = scrolledtext.ScrolledText(self.results_frame, width=80, height=20)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.file_tab, variable=self.progress_var, maximum=100)

    def _create_hash_lookup_widgets(self):
        # Hash input frame
        self.hash_frame = ttk.LabelFrame(self.hash_tab, text="Hash Input", padding="5")
        
        # Hash type selection
        self.hash_type_var = tk.StringVar(value="md5")
        self.hash_type_frame = ttk.Frame(self.hash_frame)
        ttk.Label(self.hash_type_frame, text="Hash Type:").pack(side='left', padx=5)
        ttk.Radiobutton(self.hash_type_frame, text="MD5", variable=self.hash_type_var, 
                       value="md5").pack(side='left', padx=5)
        ttk.Radiobutton(self.hash_type_frame, text="SHA-1", variable=self.hash_type_var,
                       value="sha1").pack(side='left', padx=5)
        ttk.Radiobutton(self.hash_type_frame, text="SHA-256", variable=self.hash_type_var,
                       value="sha256").pack(side='left', padx=5)
        
        # Hash input
        self.hash_input_frame = ttk.Frame(self.hash_frame)
        ttk.Label(self.hash_input_frame, text="Enter Hash:").pack(side='left', padx=5)
        self.hash_entry = ttk.Entry(self.hash_input_frame, textvariable=self.hash_input, width=70)
        self.hash_entry.pack(side='left', padx=5)
        
        # Hash lookup button
        self.lookup_button = ttk.Button(self.hash_frame, text="Lookup Hash",
                                      command=self._lookup_hash)
        
        # Hash results area
        self.hash_results_frame = ttk.LabelFrame(self.hash_tab, text="Lookup Results", padding="5")
        self.hash_results_text = scrolledtext.ScrolledText(self.hash_results_frame, width=80, height=25)

    def _create_layout(self):
        # Add notebook to root
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)

        # File Analysis Tab Layout
        self.file_frame.pack(fill='x', padx=5, pady=5)
        self.file_entry.pack(side='left', padx=5)
        self.browse_button.pack(side='left', padx=5)

        self.options_frame.pack(fill='x', padx=5, pady=5)
        self.sandbox_check.pack(side='left', padx=5)

        self.control_frame.pack(fill='x', padx=5, pady=5)
        self.analyze_button.pack(side='left', padx=5)
        self.stop_button.pack(side='left', padx=5)
        self.save_button.pack(side='left', padx=5)

        self.progress_bar.pack(fill='x', padx=5, pady=5)
        self.results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)

        # Hash Lookup Tab Layout
        self.hash_frame.pack(fill='x', padx=5, pady=5)
        self.hash_type_frame.pack(fill='x', padx=5, pady=5)
        self.hash_input_frame.pack(fill='x', padx=5, pady=5)
        self.lookup_button.pack(pady=10)
        self.hash_results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.hash_results_text.pack(fill='both', expand=True, padx=5, pady=5)

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

    def _lookup_hash(self):
        """Lookup a hash using VirusTotal API"""
        hash_value = self.hash_input.get().strip()
        hash_type = self.hash_type_var.get()
        
        # Validate hash format
        if not self._validate_hash(hash_value, hash_type):
            messagebox.showerror("Invalid Hash", 
                               f"Please enter a valid {hash_type.upper()} hash.")
            return

        self.hash_results_text.delete(1.0, tk.END)
        self.hash_results_text.insert(tk.END, f"Looking up {hash_type.upper()} hash: {hash_value}\n\n")
        self.lookup_button.config(state='disabled')
        
        threading.Thread(target=self._perform_hash_lookup, 
                       args=(hash_value,), daemon=True).start()

    def _validate_hash(self, hash_value, hash_type):
        """Validate hash format based on type"""
        if not hash_value:
            return False
            
        expected_lengths = {
            "md5": 32,
            "sha1": 40,
            "sha256": 64
        }
        
        if len(hash_value) != expected_lengths.get(hash_type, 0):
            return False
            
        # Check if hash contains only valid hexadecimal characters
        try:
            int(hash_value, 16)
            return True
        except ValueError:
            return False

    def _perform_hash_lookup(self, hash_value):
        """Perform the actual hash lookup"""
        try:
            vt_analyzer = VTAnalyzer()
            results = vt_analyzer.get_file_report(hash_value)
            
            if 'error' in results:
                self.hash_results_text.insert(tk.END, f"Error: {results['error']}\n")
            else:
                self.hash_results_text.insert(tk.END, json.dumps(results, indent=4))
                
        except Exception as e:
            self.hash_results_text.insert(tk.END, f"Error during lookup: {str(e)}\n")
        finally:
            self.lookup_button.config(state='normal')

def main():
    root = tk.Tk()
    app = FileAnalyzerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main() 