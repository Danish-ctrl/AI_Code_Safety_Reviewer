# ai_fix_coach.py

import json
import os


def get_manual_fallback(finding):
    """
    Used when AI is not enabled or API key is missing.
    This keeps the tool working even without AI.
    """

    return {
        "ai_summary": finding.get("message", "Security issue detected."),
        "before_code": finding.get("code", ""),
        "after_code": finding.get("safe_example", "No safer example available."),
        "ai_explanation": finding.get("why_risky", "This code may introduce security risk."),
        "ai_fix_steps": finding.get("suggestion", "Review and fix this issue manually."),
    }


def generate_ai_fix(finding):
    """
    Uses OpenAI API to generate a better fix explanation and safer code.

    Input:
        finding -> one issue dictionary from rules.py

    Output:
        dictionary with AI-generated fix details
    """

    if not os.getenv("OPENAI_API_KEY"):
        return get_manual_fallback(finding)

    try:
        from openai import OpenAI

        client = OpenAI()

        prompt = f"""
You are an application security code reviewer.

Review this security finding and return ONLY valid JSON.

Finding:
Rule: {finding.get("rule")}
Severity: {finding.get("severity")}
Message: {finding.get("message")}
Detected Code:
{finding.get("code")}

Manual suggestion:
{finding.get("suggestion")}

Return JSON with exactly these keys:
- ai_summary
- before_code
- after_code
- ai_explanation
- ai_fix_steps

Rules:
- Keep explanation beginner-friendly.
- after_code must be safer replacement code.
- Do not include markdown.
- Do not invent unrelated code.
"""

        response = client.responses.create(
            model="gpt-5.5",
            input=prompt,
        )

        ai_text = response.output_text.strip()
        return json.loads(ai_text)

    except Exception as error:
        fallback = get_manual_fallback(finding)
        fallback["ai_explanation"] += f" AI fallback used because: {error}"
        return fallback


def enrich_findings_with_ai(findings, use_ai=False):
    """
    Adds AI Fix Coach information to every finding.

    If use_ai=False, it uses manual fallback.
    If use_ai=True and OPENAI_API_KEY exists, it calls AI.
    """

    enriched_findings = []

    for finding in findings:
        if use_ai:
            ai_fix = generate_ai_fix(finding)
        else:
            ai_fix = get_manual_fallback(finding)

        finding["ai_fix"] = ai_fix
        enriched_findings.append(finding)

    return enriched_findings