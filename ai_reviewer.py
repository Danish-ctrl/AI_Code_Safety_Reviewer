# ai_reviewer.py


def generate_ai_review(finding):
    rule = finding["rule"]
    code = finding["code"]

    if rule == "Dangerous eval usage":
        return (
            "This code uses eval(), which executes text as Python code. "
            "If the input is controlled by a user, they could run malicious code. "
            "A safer approach is to avoid eval() and use specific parsing methods like int(), "
            "float(), json.loads(), or a whitelist of allowed actions."
        )

    if rule == "Dangerous exec usage":
        return (
            "This code uses exec(), which can execute dynamic Python code. "
            "This is risky because it may allow unexpected or malicious behavior. "
            "A safer approach is to move the logic into normal Python functions instead of executing strings."
        )

    if rule == "Hardcoded password":
        return (
            "A password appears to be written directly in the source code. "
            "This is risky because anyone with access to the code can see it. "
            "Use environment variables, a .env file, or a secure secret manager instead."
        )

    if rule == "Hardcoded API key":
        return (
            "An API key appears to be hardcoded in the source code. "
            "If this code is pushed to GitHub or shared, the key may be leaked. "
            "Move API keys outside the code using environment variables or a secret manager."
        )

    if rule == "Hardcoded secret":
        return (
            "A secret or token appears to be stored directly in the code. "
            "Secrets should not be committed into source control. "
            "Store them securely using environment variables or a dedicated secret manager."
        )

    if rule == "Shell command execution":
        return (
            "This code executes a system command. "
            "Shell command execution can be risky, especially when user input is involved. "
            "Prefer built-in Python libraries where possible and avoid passing raw input into commands."
        )

    if rule == "User input passed to dangerous function":
        return (
            "User input is being passed into a dangerous function. "
            "This can allow command injection or arbitrary code execution depending on the function. "
            "Validate input strictly, use allowlists, and avoid executing user-controlled values."
        )

    return (
        f"This issue was detected by the rule '{rule}'. "
        f"Review this code carefully: {code}. "
        "Consider replacing risky behavior with a safer and more controlled approach."
    )


def add_ai_reviews(findings):
    for finding in findings:
        finding["ai_review"] = generate_ai_review(finding)

    return findings