import hashlib

class HashAnalyzer:
    def __init__(self):
        self.block_size = 65536

    def calculate_hashes(self, file_path):
        """
        Calculate MD5, SHA-1, and SHA-256 hashes for a given file
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        try:
            with open(file_path, 'rb') as f:
                while True:
                    data = f.read(self.block_size)
                    if not data:
                        break
                    md5.update(data)
                    sha1.update(data)
                    sha256.update(data)

            return {
                'md5': md5.hexdigest(),
                'sha1': sha1.hexdigest(),
                'sha256': sha256.hexdigest()
            }
        except Exception as e:
            return {
                'error': f"Error calculating hashes: {str(e)}"
            } 