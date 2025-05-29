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
            # Get the file analysis from VirusTotal
            file_info = self.client.get_object(f"/files/{file_hash}")
            
            # Check if we have analysis results
            if not hasattr(file_info, 'last_analysis_stats'):
                return {'error': 'No analysis results available for this hash'}

            # Extract relevant information
            last_analysis_stats = file_info.last_analysis_stats
            last_analysis_results = {}
            
            # Get detailed scan results if available
            if hasattr(file_info, 'last_analysis_results'):
                for engine_name, result in file_info.last_analysis_results.items():
                    last_analysis_results[engine_name] = {
                        'category': result.get('category', 'unknown'),
                        'result': result.get('result', None),
                        'method': result.get('method', 'unknown'),
                        'engine_name': result.get('engine_name', engine_name)
                    }

            # Prepare the response
            response = {
                'stats': {
                    'malicious': last_analysis_stats.get('malicious', 0),
                    'suspicious': last_analysis_stats.get('suspicious', 0),
                    'undetected': last_analysis_stats.get('undetected', 0),
                    'timeout': last_analysis_stats.get('timeout', 0),
                    'failure': last_analysis_stats.get('failure', 0)
                },
                'total_scans': sum(last_analysis_stats.values()),
                'scan_results': last_analysis_results
            }

            # Add additional file information if available
            if hasattr(file_info, 'meaningful_name'):
                response['file_name'] = file_info.meaningful_name
            if hasattr(file_info, 'size'):
                response['file_size'] = file_info.size
            if hasattr(file_info, 'type_tag'):
                response['file_type'] = file_info.type_tag

            return response

        except vt.error.APIError as e:
            if str(e).startswith('NotFoundError'):
                return {'error': 'Hash not found in VirusTotal database'}
            return {'error': f"VirusTotal API error: {str(e)}"}
        except Exception as e:
            return {'error': f"Error getting file report: {str(e)}"}
        finally:
            try:
                self.client.close()
            except:
                pass

    def __del__(self):
        """
        Close the VirusTotal client
        """
        try:
            self.client.close()
        except:
            pass 