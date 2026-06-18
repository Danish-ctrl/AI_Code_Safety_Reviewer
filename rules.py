# rules.py

import re


RISKY_PATTERNS = [
    {
        "rule_id": "PY-SEC-001",
        "name": "Dangerous eval usage",
        "pattern": r"\beval\s*\(",
        "message": "Use of eval() can be dangerous because it executes dynamic code.",
        "why_risky": "eval() can run any Python code. If user input reaches eval(), an attacker may execute harmful commands.",
        "attack_example": "__import__('os').system('whoami')",
        "suggestion": "Avoid eval(). Use safer alternatives like int(), float(), json.loads(), or a whitelist of allowed values.",
        "safe_example": "allowed_actions = {'start': start_function, 'stop': stop_function}",
        "severity": "HIGH",
        "confidence": "HIGH",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-002",
        "name": "Dangerous exec usage",
        "pattern": r"\bexec\s*\(",
        "message": "Use of exec() can be dangerous because it executes dynamic Python code.",
        "why_risky": "exec() can execute full Python blocks, making it very risky when used with dynamic or user-controlled input.",
        "attack_example": "exec(\"import os; os.system('whoami')\")",
        "suggestion": "Avoid exec(). Move logic into normal Python functions instead of executing dynamic code.",
        "safe_example": "def run_task():\n    print('Run safe predefined logic')",
        "severity": "HIGH",
        "confidence": "HIGH",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-003",
        "name": "Hardcoded password",
        "pattern": r"(password|passwd|pwd)\s*=\s*[\"'].+[\"']",
        "message": "Possible hardcoded password found.",
        "why_risky": "Passwords stored in code can leak through GitHub, logs, backups, or shared project files.",
        "attack_example": "password = 'admin123'",
        "suggestion": "Do not store passwords in code. Use environment variables or a secret manager.",
        "safe_example": "import os\npassword = os.getenv('APP_PASSWORD')",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-004",
        "name": "Hardcoded API key",
        "pattern": r"(api_key|apikey|access_key)\s*=\s*[\"'].+[\"']",
        "message": "Possible hardcoded API key found.",
        "why_risky": "API keys in source code can be stolen and used to access paid services or private systems.",
        "attack_example": "api_key = 'abc-123-secret'",
        "suggestion": "Move API keys to environment variables, a .env file, or a secure secret manager.",
        "safe_example": "import os\napi_key = os.getenv('API_KEY')",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-005",
        "name": "Hardcoded secret",
        "pattern": r"(secret|token)\s*=\s*[\"'].+[\"']",
        "message": "Possible hardcoded secret or token found.",
        "why_risky": "Secrets and tokens can allow unauthorized access if they are pushed to a repository.",
        "attack_example": "token = 'secret-token-123'",
        "suggestion": "Move secrets and tokens outside source code. Use environment variables or a secret manager.",
        "safe_example": "import os\ntoken = os.getenv('ACCESS_TOKEN')",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-006",
        "name": "Shell command execution",
        "pattern": r"(os\.system|subprocess\.run|subprocess\.call|subprocess\.Popen)\s*\(",
        "message": "Shell command execution found. Be careful if user input is passed into commands.",
        "why_risky": "Shell commands can become dangerous if user-controlled values are included.",
        "attack_example": "os.system(user_input)",
        "suggestion": "Avoid shell=True and avoid passing raw user input into shell commands. Prefer safe Python libraries where possible.",
        "safe_example": "subprocess.run(['ls', '-l'], check=True)",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "specificity": 1,
    },
    {
        "rule_id": "PY-SEC-008",
        "name": "Unsafe pickle deserialization",
        "pattern": r"\bpickle\.(load|loads)\s*\(",
        "message": "Use of pickle load/loads detected.",
        "why_risky": "pickle can execute code during deserialization if the input data is malicious.",
        "attack_example": "pickle.loads(user_controlled_data)",
        "suggestion": "Avoid pickle for untrusted data. Use JSON or another safe serialization format when possible.",
        "safe_example": "import json\ndata = json.loads(json_text)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-009",
        "name": "Unsafe YAML load",
        "pattern": r"\byaml\.load\s*\(",
        "message": "yaml.load() detected. It can be unsafe if used without SafeLoader.",
        "why_risky": "Unsafe YAML loading may construct arbitrary Python objects from malicious YAML content.",
        "attack_example": "yaml.load(user_yaml)",
        "suggestion": "Use yaml.safe_load() for untrusted YAML content.",
        "safe_example": "data = yaml.safe_load(yaml_text)",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-010",
        "name": "Subprocess with shell=True",
        "pattern": r"(subprocess\.run|subprocess\.call|subprocess\.Popen)\s*\([^)]*shell\s*=\s*True",
        "message": "subprocess used with shell=True.",
        "why_risky": "shell=True can allow shell injection if command values include user input.",
        "attack_example": "subprocess.run(user_input, shell=True)",
        "suggestion": "Avoid shell=True. Pass command arguments as a list instead.",
        "safe_example": "subprocess.run(['ls', '-l'], check=True)",
        "severity": "HIGH",
        "confidence": "HIGH",
        "specificity": 3,
    },
    {
        "rule_id": "PY-SEC-011",
        "name": "SSL verification disabled",
        "pattern": r"requests\.(get|post|put|delete|patch)\s*\([^)]*verify\s*=\s*False",
        "message": "SSL certificate verification is disabled in requests call.",
        "why_risky": "Disabling SSL verification makes the connection vulnerable to man-in-the-middle attacks.",
        "attack_example": "requests.get('https://example.com', verify=False)",
        "suggestion": "Keep SSL verification enabled. Remove verify=False unless there is a very controlled reason.",
        "safe_example": "response = requests.get('https://example.com')",
        "severity": "HIGH",
        "confidence": "HIGH",
        "specificity": 3,
    },
    {
        "rule_id": "PY-SEC-012",
        "name": "Flask debug mode enabled",
        "pattern": r"\.run\s*\([^)]*debug\s*=\s*True",
        "message": "Flask debug mode appears to be enabled.",
        "why_risky": "Debug mode can expose sensitive application details and interactive debugging features.",
        "attack_example": "app.run(debug=True)",
        "suggestion": "Disable debug mode in production. Use environment-based configuration.",
        "safe_example": "app.run(debug=False)",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-013",
        "name": "Django DEBUG enabled",
        "pattern": r"\bDEBUG\s*=\s*True",
        "message": "Django DEBUG appears to be enabled.",
        "why_risky": "DEBUG=True can expose sensitive error pages and configuration details in production.",
        "attack_example": "DEBUG = True",
        "suggestion": "Set DEBUG=False in production and control it using environment variables.",
        "safe_example": "import os\nDEBUG = os.getenv('DJANGO_DEBUG') == 'true'",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-014",
        "name": "Insecure temporary file creation",
        "pattern": r"\btempfile\.mktemp\s*\(",
        "message": "tempfile.mktemp() detected.",
        "why_risky": "mktemp() can create race-condition risks because the file is not securely opened.",
        "attack_example": "path = tempfile.mktemp()",
        "suggestion": "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead.",
        "safe_example": "with tempfile.NamedTemporaryFile() as temp_file:\n    temp_file.write(b'data')",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "specificity": 2,
    },
    {
        "rule_id": "PY-SEC-015",
        "name": "Possible SQL string construction",
        "pattern": r"(SELECT|INSERT|UPDATE|DELETE).*(\+|%|\.format\s*\(|f[\"'])",
        "message": "Possible SQL query built using string formatting or concatenation.",
        "why_risky": "Building SQL queries with string formatting can lead to SQL injection if user input is included.",
        "attack_example": "query = 'SELECT * FROM users WHERE name=' + user_input",
        "suggestion": "Use parameterized queries instead of string concatenation or formatting.",
        "safe_example": "cursor.execute('SELECT * FROM users WHERE name = ?', (user_input,))",
        "severity": "HIGH",
        "confidence": "LOW",
        "specificity": 1,
    },
]


DANGEROUS_FUNCTIONS = [
    "eval",
    "exec",
    "os.system",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "pickle.loads",
    "pickle.load",
    "yaml.load",
]


def is_comment(line):
    stripped_line = line.strip()
    return stripped_line.startswith("#")


def should_ignore_line(line):
    """
    Allows developers to ignore a finding intentionally.

    Example:
        eval(test_code)  # ai-reviewer: ignore
    """

    return "ai-reviewer: ignore" in line.lower()


def find_user_input_variables(lines):
    """
    Finds variables that directly store user input.

    Example:
        command = input("Enter command: ")

    Output:
        {"command"}
    """

    user_input_variables = set()

    input_pattern = r"([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*input\s*\("

    for line in lines:
        if is_comment(line) or should_ignore_line(line):
            continue

        match = re.search(input_pattern, line)

        if match:
            variable_name = match.group(1)
            user_input_variables.add(variable_name)

    return user_input_variables


def check_user_input_in_dangerous_functions(file_path, lines, user_input_variables):
    findings = []

    for line_number, line in enumerate(lines, start=1):
        if is_comment(line) or should_ignore_line(line):
            continue

        for variable in user_input_variables:
            for dangerous_function in DANGEROUS_FUNCTIONS:
                pattern = rf"{re.escape(dangerous_function)}\s*\([^)]*\b{variable}\b[^)]*\)"

                if re.search(pattern, line):
                    findings.append({
                        "file": file_path,
                        "line": line_number,
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "rule_id": "PY-SEC-007",
                        "rule": "User input passed to dangerous function",
                        "message": f"User input variable '{variable}' is passed into {dangerous_function}(). This can be unsafe.",
                        "why_risky": "User input should not directly control dangerous functions. Attackers may enter unexpected values that execute harmful behavior.",
                        "attack_example": "User enters: __import__('os').system('whoami')",
                        "suggestion": "Validate or sanitize user input before using it. Prefer allowlists and safer APIs instead of executing user-controlled values.",
                        "safe_example": "allowed_commands = {'list': list_files}\nif command in allowed_commands:\n    allowed_commands[command]()",
                        "code": line.strip(),
                        "specificity": 4,
                    })

    return findings


def deduplicate_findings(findings):
    """
    Removes weaker duplicate findings from the same file and line.

    Priority:
        1. Higher severity
        2. Higher confidence
        3. Higher specificity
    """

    severity_rank = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    confidence_rank = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    best_findings = {}

    for finding in findings:
        key = (finding.get("file"), finding.get("line"))

        if key not in best_findings:
            best_findings[key] = finding
            continue

        existing = best_findings[key]

        finding_severity_rank = severity_rank.get(finding.get("severity", "MEDIUM"), 0)
        existing_severity_rank = severity_rank.get(existing.get("severity", "MEDIUM"), 0)

        finding_confidence_rank = confidence_rank.get(finding.get("confidence", "MEDIUM"), 0)
        existing_confidence_rank = confidence_rank.get(existing.get("confidence", "MEDIUM"), 0)

        finding_specificity = finding.get("specificity", 1)
        existing_specificity = existing.get("specificity", 1)

        if finding_severity_rank > existing_severity_rank:
            best_findings[key] = finding
        elif finding_severity_rank == existing_severity_rank:
            if finding_confidence_rank > existing_confidence_rank:
                best_findings[key] = finding
            elif finding_confidence_rank == existing_confidence_rank:
                if finding_specificity > existing_specificity:
                    best_findings[key] = finding

    return list(best_findings.values())


def scan_code(file_path, code_text):
    findings = []

    lines = code_text.splitlines()

    user_input_variables = find_user_input_variables(lines)

    for line_number, line in enumerate(lines, start=1):
        if is_comment(line) or should_ignore_line(line):
            continue

        for rule in RISKY_PATTERNS:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "file": file_path,
                    "line": line_number,
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "rule_id": rule["rule_id"],
                    "rule": rule["name"],
                    "message": rule["message"],
                    "why_risky": rule["why_risky"],
                    "attack_example": rule["attack_example"],
                    "suggestion": rule["suggestion"],
                    "safe_example": rule["safe_example"],
                    "code": line.strip(),
                    "specificity": rule["specificity"],
                })

    smarter_findings = check_user_input_in_dangerous_functions(
        file_path,
        lines,
        user_input_variables
    )

    findings.extend(smarter_findings)

    return deduplicate_findings(findings)