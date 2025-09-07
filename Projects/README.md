
# WebVuln Scanner 

## Contents
- scanner.py (CLI scanner)
- app.py (Flask UI)
- requirements.txt
- README.md (this file)
- reports/ (sample reports & generated outputs)
- Web_Application_Vulnerability_Scanner_Report.pdf (project report)

## Quickstart
1. Create venv and activate:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. CLI scan (passive):
   ```bash
   python scanner.py --url http://example.com --max-pages 5 --active 0
   ```
4. Start UI:
   ```bash
   python app.py
   # then open http://127.0.0.1:5000
   ```

## Note
- Only scan targets in allowlist (edit scanner.py to change).
- Active tests should only be used on lab targets like testphp.vulnweb.com
