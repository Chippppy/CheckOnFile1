# File Analyzer Tool

A comprehensive file analysis tool that provides detailed analysis of various file types including executables, documents, and images. The tool includes features for file hashing, VirusTotal integration, PE file analysis, and basic sandbox behavior monitoring.

## Features

- File hash generation (MD5, SHA-1, SHA-256)
- VirusTotal API integration for malware detection
- PE file analysis for executable files
- Basic sandbox behavior monitoring
- Support for multiple file types:
  - Executable files (.exe, .dll)
  - Document files (Word, Excel, PowerPoint)
  - Image files
  - Text files
- Both CLI and GUI interfaces

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
├── requirements.txt
└── README.md
```

## Troubleshooting

1. If you encounter issues with python-magic on Windows:
   - The package `python-magic-bin` is automatically installed for Windows systems
   - Make sure you're running the tool from within the activated virtual environment

2. VirusTotal API Issues:
   - Ensure your API key is correctly set in the `.env` file
   - Check your API key permissions on the VirusTotal website
   - Verify your internet connection

3. Sandbox Monitoring:
   - Requires administrative privileges for some features
   - May be blocked by antivirus software
