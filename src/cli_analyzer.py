import argparse
import json
import os
from analyzer.hash_analyzer import HashAnalyzer
from analyzer.pe_analyzer import PEAnalyzer
from analyzer.vt_analyzer import VTAnalyzer
from analyzer.sandbox_monitor import SandboxMonitor
from analyzer.document_analyzer import DocumentAnalyzer

def main():
    parser = argparse.ArgumentParser(description='File Analysis Tool')
    parser.add_argument('--file', required=True, help='Path to the file to analyze')
    parser.add_argument('--sandbox', action='store_true', help='Enable sandbox monitoring')
    parser.add_argument('--output', help='Output file for results (JSON format)')
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File {args.file} not found")
        return

    results = {
        'file_path': args.file,
        'file_name': os.path.basename(args.file)
    }

    # Calculate file hashes
    print("Calculating file hashes...")
    hash_analyzer = HashAnalyzer()
    results['hashes'] = hash_analyzer.calculate_hashes(args.file)

    # Analyze with VirusTotal
    print("Scanning with VirusTotal...")
    vt_analyzer = VTAnalyzer()
    vt_results = vt_analyzer.scan_file(args.file)
    if 'error' not in vt_results:
        results['virustotal'] = vt_analyzer.get_file_report(results['hashes']['sha256'])
    else:
        results['virustotal'] = vt_results

    # Document analysis
    print("Analyzing document properties...")
    doc_analyzer = DocumentAnalyzer()
    results['document_analysis'] = doc_analyzer.analyze_file(args.file)

    # PE analysis if applicable
    if args.file.lower().endswith(('.exe', '.dll', '.sys')):
        print("Performing PE analysis...")
        pe_analyzer = PEAnalyzer()
        results['pe_analysis'] = pe_analyzer.analyze_pe(args.file)

        # Sandbox monitoring if requested
        if args.sandbox:
            print("Starting sandbox monitoring...")
            sandbox = SandboxMonitor()
            monitor_results = sandbox.start_monitoring(args.file)
            
            if 'error' not in monitor_results:
                input("Press Enter to stop monitoring...")
                results['sandbox_analysis'] = sandbox.stop_monitoring()
            else:
                results['sandbox_analysis'] = monitor_results

    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\nResults saved to {args.output}")
    else:
        print("\nAnalysis Results:")
        print(json.dumps(results, indent=4))

if __name__ == '__main__':
    main() 