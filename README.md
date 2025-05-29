# File Analyzer Tool

A comprehensive file analysis tool that provides detailed analysis of various file types including executables, documents, and images. The tool includes features for file hashing, VirusTotal integration, PE file analysis, and basic sandbox behavior monitoring.

## Features

- File Analysis:
  - File hash generation (MD5, SHA-1, SHA-256)
  - VirusTotal API integration for malware detection
  - PE file analysis for executable files
  - Basic sandbox behavior monitoring
  - Support for multiple file types:
    - Executable files (.exe, .dll)
    - Document files (Word, Excel, PowerPoint)
    - Image files
    - Text files

- Hash Lookup:
  - Direct hash lookup using VirusTotal API
  - Support for multiple hash types:
    - MD5
    - SHA-1
    - SHA-256
  - Detailed scan results from multiple antivirus engines
  - Malware detection statistics

- Interface Options:
  - Modern GUI with tabbed interface
  - Command-line interface
  - Results saving functionality

## Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd file-analyzer
   ```

2. Create and activate a virtual environment:
   ```bash
   # Windows
   python -m venv venv
   .\venv\Scripts\activate

   # Linux/Mac
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up your VirusTotal API key:
   ```bash
   # Create .env file
   echo VT_API_KEY=your_api_key_here > .env
   ```
   Replace `your_api_key_here` with your actual VirusTotal API key.

## Usage

### GUI Mode
With the virtual environment activated:
```bash
python src/gui_analyzer.py
```

The GUI provides two main functions:
1. File Analysis Tab:
   - Select and analyze files
   - Enable sandbox monitoring for executables
   - View and save detailed analysis results

2. Hash Lookup Tab:
   - Enter file hashes directly
   - Select hash type (MD5, SHA-1, SHA-256)
   - Get instant VirusTotal scan results

### CLI Mode
With the virtual environment activated:
```bash
python src/cli_analyzer.py --file path/to/file [--sandbox] [--output results.json]
```

Options:
- `--file`: Path to the file to analyze (required)
- `--sandbox`: Enable sandbox monitoring (optional)
- `--output`: Save results to a JSON file (optional)

## Requirements

- Python 3.8+
- VirusTotal API key
- Windows OS (for full PE analysis functionality)
- Virtual environment (recommended)

## Project Structure

```
file_analyzer/
├── src/
│   ├── __init__.py
│   ├── analyzer/
│   │   ├── __init__.py
│   │   ├── hash_analyzer.py
│   │   ├── pe_analyzer.py
│   │   ├── vt_analyzer.py
│   │   ├── sandbox_monitor.py
│   │   └── document_analyzer.py
│   ├── gui_analyzer.py
│   └── cli_analyzer.py
├── Artemis Malware Example - theZoo/
│   ├── Artemis.md5
│   ├── Artemis.sha256
├── requirements.txt
└── README.md
```

## Troubleshooting

1. VirusTotal API Issues:
   - Ensure your API key is correctly set in the `.env` file
   - Check your API key permissions on the VirusTotal website
   - Verify your internet connection

2. Hash Lookup Issues:
   - Verify the hash is in the correct format for the selected hash type
   - MD5: 32 characters
   - SHA-1: 40 characters
   - SHA-256: 64 characters
   - Make sure you're using hexadecimal characters only (0-9, a-f)

3. Sandbox Monitoring:
   - Requires administrative privileges for some features
   - May be blocked by antivirus software
