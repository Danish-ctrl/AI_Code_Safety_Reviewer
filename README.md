# 🛡️ AI Code Safety Reviewer

An AI-powered desktop application that scans Python projects for common security issues, detects unsafe coding patterns, and provides AI-generated explanations and remediation suggestions.

Designed as a practical cybersecurity portfolio project, this application combines static code analysis with AI assistance to help developers write safer Python code.

---

## ✨ Features

* 🔍 Scan an entire Python project for security issues
* 🤖 AI-powered explanations for detected vulnerabilities
* 💡 Suggested fixes and secure coding recommendations
* 📄 Generate detailed HTML security reports
* 📚 Maintain scan history for previous analyses
* 🖥️ Simple desktop GUI built with Tkinter
* ⚡ Fast local static analysis before AI review

---

## Demo

> *(Add screenshots or a GIF here after the project is finalized.)*

---

## Project Structure

```text
AI_Code_Safety_Reviewer/
│
├── ai_fix_coach.py
├── ai_reviewer.py
├── config.py
├── file_loader.py
├── gui_app.py
├── history_manager.py
├── report_generator.py
├── rules.py
├── scanner.py
├── requirements.txt
│
├── sample_project/
│
└── README.md
```

---

## Technologies Used

* Python 3
* Tkinter
* OpenAI API
* HTML Report Generation
* Static Code Analysis
* Git & GitHub

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Danish-ctrl/AI_Code_Safety_Reviewer.git
```

Move into the project directory:

```bash
cd AI_Code_Safety_Reviewer
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it.

Windows

```bash
venv\Scripts\activate
```

Linux / macOS

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Configuration

Create a `.env` file or update `config.py` with your OpenAI API key.

Example:

```python
OPENAI_API_KEY = "your_api_key_here"
```

---

## Running the Application

```bash
python gui_app.py
```

---

## Example Workflow

1. Select a Python project.
2. Start the scan.
3. Review detected vulnerabilities.
4. Read AI-generated explanations.
5. Export the HTML report.

---

## Example Security Checks

* Hardcoded passwords
* Dangerous `eval()` usage
* Shell command execution
* Weak exception handling
* Insecure file operations
* Potential code injection
* Unsafe imports

---

## Future Improvements (Version 2)

* CVE reference integration
* Multi-language support
* PDF report export
* Plugin architecture
* Batch scanning
* GitHub repository scanning
* Local AI model support

---

## License

This project is licensed under the MIT License.

---

## Author

**Danish**

Cybersecurity • Python • AI • Secure Software Development

GitHub:
https://github.com/Danish-ctrl
