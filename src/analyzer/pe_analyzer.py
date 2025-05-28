import pefile
import datetime

class PEAnalyzer:
    def __init__(self):
        self.pe = None

    def analyze_pe(self, file_path):
        """
        Analyze PE file and extract important information
        """
        try:
            self.pe = pefile.PE(file_path)
            return {
                'basic_info': self._get_basic_info(),
                'sections': self._get_sections_info(),
                'imports': self._get_imports_info(),
                'exports': self._get_exports_info()
            }
        except Exception as e:
            return {'error': f"Error analyzing PE file: {str(e)}"}

    def _get_basic_info(self):
        """Extract basic information from PE file"""
        try:
            return {
                'Machine': hex(self.pe.FILE_HEADER.Machine),
                'TimeDateStamp': datetime.datetime.fromtimestamp(
                    self.pe.FILE_HEADER.TimeDateStamp
                ).strftime('%Y-%m-%d %H:%M:%S'),
                'Characteristics': hex(self.pe.FILE_HEADER.Characteristics),
                'EntryPoint': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'ImageBase': hex(self.pe.OPTIONAL_HEADER.ImageBase)
            }
        except:
            return {}

    def _get_sections_info(self):
        """Extract information about PE sections"""
        sections = []
        try:
            for section in self.pe.sections:
                sections.append({
                    'Name': section.Name.decode().rstrip('\x00'),
                    'VirtualAddress': hex(section.VirtualAddress),
                    'VirtualSize': hex(section.Misc_VirtualSize),
                    'RawSize': hex(section.SizeOfRawData),
                    'Characteristics': hex(section.Characteristics)
                })
        except:
            pass
        return sections

    def _get_imports_info(self):
        """Extract information about imported functions"""
        imports = {}
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                imports[entry.dll.decode()] = [
                    func.name.decode() if func.name else str(func.ordinal)
                    for func in entry.imports
                ]
        except:
            pass
        return imports

    def _get_exports_info(self):
        """Extract information about exported functions"""
        exports = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append({
                        'name': exp.name.decode() if exp.name else '',
                        'address': hex(self.pe.OPTIONAL_HEADER.ImageBase + exp.address),
                        'ordinal': exp.ordinal
                    })
        except:
            pass
        return exports 