# HackGuard AI — Security Awareness Dashboard

A student-friendly cybersecurity project built with Flask, HTML, CSS, and JavaScript. It performs a **basic HTTP/HTTPS and security-header checklist** for a public website and displays the findings in a dashboard.

> This starter project does **not** use an AI model yet and is **not** a full penetration-testing tool. It does not exploit vulnerabilities, brute-force passwords, or scan ports. The name “AI” is a project concept/placeholder; connect a model only after configuring a trusted provider and protecting API keys.

## Features
- Modern dark cybersecurity dashboard
- Basic website reachability and HTTP response check
- HTTPS and common security-header checklist
- Score visualization and findings chart
- CSV report download
- Friendly validation and timeout handling

## Requirements
- Python 3.10+
- Internet access for checking a public website

## Run on Windows
1. Extract the ZIP file.
2. Open the extracted `HackGuard_AI` folder in VS Code.
3. Open Terminal → New Terminal.
4. Create a virtual environment:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks activation, use Command Prompt and run:
   ```bat
   .venv\Scripts\activate.bat
   ```
5. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
6. Start the site:
   ```bash
   python app.py
   ```
7. Open `http://127.0.0.1:5000` in your browser.

## Safe use
Only test public websites you own or are explicitly authorized to assess. The checker makes a single ordinary HTTP(S) request and inspects the response headers. It does not prove a website is secure. A missing header may be intentional depending on the site's architecture; review findings with a qualified administrator. Do not enter passwords, tokens, or other secrets.

## Project structure
```text
HackGuard_AI/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── templates/
    └── index.html
```
