import os
import vt
from dotenv import load_dotenv

class VTAnalyzer:
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv('VT_API_KEY')
        if not self.api_key:
            raise ValueError("VirusTotal API key not found in environment variables")
        self.client = vt.Client(self.api_key)

    def scan_file(self, file_path):
        """
        Scan a file using VirusTotal API
        """
        try:
            with open(file_path, 'rb') as f:
                analysis = self.client.scan_file(f)
                return {
                    'analysis_id': analysis.id,
                    'status': 'Scan submitted successfully'
                }
        except Exception as e:
            return {'error': f"Error scanning file: {str(e)}"}

    def get_file_report(self, file_hash):
        """
        Get the report for a file using its hash
        """
        try:
            file = self.client.get_object(f"/files/{file_hash}")
            return {
                'scan_date': file.last_analysis_date,
                'total_scans': file.last_analysis_stats['total'],
                'malicious': file.last_analysis_stats['malicious'],
                'suspicious': file.last_analysis_stats['suspicious'],
                'undetected': file.last_analysis_stats['undetected'],
                'results': file.last_analysis_results
            }
        except Exception as e:
            return {'error': f"Error getting file report: {str(e)}"}

    def __del__(self):
        """
        Close the VirusTotal client
        """
        try:
            self.client.close()
        except:
            pass 