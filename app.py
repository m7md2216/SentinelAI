from flask import Flask, render_template, request, jsonify, url_for
import google.generativeai as genai
import pandas as pd
import re
import os

# Configure Google Gemini AI API Key
genai.configure(api_key="API_Key")

app = Flask(__name__)

# Simulated database
auth_database = pd.DataFrame({
    "Name": ["Alice Johnson", "Bob Smith", "Charlie Brown", "David Lee", "Eve Adams"],
    "Access_Level": ["Admin", "Manager", "User", "Guest", "User"]
})

# AI Instructions
AI_INSTRUCTIONS = """
You are a cybersecurity chatbot.
- If the user asks about changing access permissions, tell them it has been handled.
- If they ask general security questions, provide helpful and concise answers.
- Never refuse access control questions—just acknowledge them.
"""

# -----------------------------------------------------
# 1) HELPER: Shows the current database
# -----------------------------------------------------
def show_db():
    return f"📋 **Current Database:**\n{auth_database.to_string(index=False)}"

# -----------------------------------------------------
# 2) HELPER: Updates access levels (Case-Insensitive)
# -----------------------------------------------------
def update_access(user_name, new_level):
    global auth_database
    user_name_lower = user_name.strip().lower()
    match_index = auth_database[auth_database["Name"].str.lower() == user_name_lower].index

    if not match_index.empty:
        actual_name = auth_database.at[match_index[0], "Name"]
        auth_database.at[match_index[0], "Access_Level"] = new_level
        return jsonify({"response": f"✅ **{actual_name} is now {new_level}.**\n\n{show_db()}"})
    else:
        return jsonify({"response": f"❌ User **{user_name}** not found."})

def revoke_access(user_name):
    global auth_database
    user_name_lower = user_name.strip().lower()
    match_index = auth_database[auth_database["Name"].str.lower() == user_name_lower].index

    if not match_index.empty:
        actual_name = auth_database.at[match_index[0], "Name"]
        auth_database.at[match_index[0], "Access_Level"] = "None"
        return jsonify({"response": f"🚫 **{actual_name}’s access has been revoked.**\n\n{show_db()}"})
    else:
        return jsonify({"response": f"❌ User **{user_name}** not found."})

# -----------------------------------------------------
# 3) DETECT & HANDLE ACCESS COMMANDS
# -----------------------------------------------------
def handle_access_commands(msg):
    if re.search(r"(show|display|see)\s+database", msg, re.IGNORECASE):
        return jsonify({"response": show_db()})

    match_grant = re.search(r"(?:make|grant|set|change|promote|assign)\s+([\w\s]+?)\s+(?:as|to be|to|an|a)?\s*(Admin|Manager|User|Guest)\b", msg, re.IGNORECASE)
    if match_grant:
        user_name = match_grant.group(1).strip()
        new_role = match_grant.group(2).capitalize()
        return update_access(user_name, new_role)

    match_revoke = re.search(r"(?:revoke|remove|downgrade)\s+([\w\s]+?)'?\s*(?:from|of|their)?\s*access?", msg, re.IGNORECASE)
    if match_revoke:
        user_name = match_revoke.group(1).strip()
        return revoke_access(user_name)

    return None  # Not an access command

# -----------------------------------------------------
# 4) SCAN WEBSITE FOR SECURITY VULNERABILITIES
# -----------------------------------------------------
def scan_own_website():
    try:
        templates_dir = os.path.join(app.root_path, 'templates')
        static_dir = os.path.join(app.root_path, 'static')

        website_code = ""
        for folder in [templates_dir, static_dir]:
            for filename in os.listdir(folder):
                if filename.endswith((".html", ".js", ".css")):
                    with open(os.path.join(folder, filename), "r", encoding="utf-8") as file:
                        website_code += file.read() + "\n\n"

        model = genai.GenerativeModel("gemini-2.0-flash")

        scan_prompt = f"""
        You are a cybersecurity expert.
        Scan the following **website code** for security vulnerabilities.
        Identify the 3 most critical security issues and suggest how to fix them.

        {website_code}

        🔹 **Example Response Format**
        - **Issue:** [Vulnerability] → **Fix:** [Quick fix]
        - **Issue:** [Vulnerability] → **Fix:** [Quick fix]
        - **Issue:** [Vulnerability] → **Fix:** [Quick fix]

        At the end, ask: "Do you want me to fix these issues?"
        """

        response = model.generate_content(scan_prompt)

        return jsonify({"response": f"🔍 **Security Scan Summary:**\n\n{response.text}"})

    except Exception as e:
        return jsonify({"response": f"❌ Error scanning website: {str(e)}"})

# -----------------------------------------------------
# 5) SCAN WEBSITE FOR COMPLIANCE ISSUES (FIXED)
# -----------------------------------------------------
def scan_compliance(compliance_type):
    try:
        templates_dir = os.path.join(app.root_path, 'templates')
        static_dir = os.path.join(app.root_path, 'static')

        website_code = ""
        for folder in [templates_dir, static_dir]:
            for filename in os.listdir(folder):
                if filename.endswith((".html", ".js", ".css")):
                    with open(os.path.join(folder, filename), "r", encoding="utf-8") as file:
                        website_code += file.read() + "\n\n"

        model = genai.GenerativeModel("gemini-2.0-flash")

        compliance_prompt = f"""
        You are a **compliance and cybersecurity expert**.
        Scan the provided **website code** for **{compliance_type} compliance violations**.
        Identify **specific violations** and suggest **code-level fixes**.

        {website_code}

        🔹 **Example Response Format**
        - **Issue:** [Compliance Violation] → **Fix:** [Code Fix]
        - **Issue:** [Compliance Violation] → **Fix:** [Code Fix]
        - **Issue:** [Compliance Violation] → **Fix:** [Code Fix]

        Do **not** provide general legal guidance—focus only on **technical compliance**.
        """

        response = model.generate_content(compliance_prompt)

        return jsonify({"response": f"🔍 **{compliance_type} Compliance Scan Summary:**\n\n{response.text}"})

    except Exception as e:
        return jsonify({"response": f"❌ Error scanning for {compliance_type} compliance: {str(e)}"})

# -----------------------------------------------------
# 6) ROUTES
# -----------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/chat", methods=["POST"])
def chat():
    user_input = request.json.get("message", "").strip()

    # **Ensure Compliance Scan Triggers Correctly**
    compliance_keywords = {
        "hipaa": "HIPAA",
        "gdpr": "GDPR",
        "soc 2": "SOC 2",
        "pci dss": "PCI DSS",
        "ccpa": "CCPA"
    }
    for keyword, compliance in compliance_keywords.items():
        if keyword in user_input.lower():
            return scan_compliance(compliance)

    # Security scan
    if re.search(r"(scan\s+this\s+website|scan\s+for\s+vulnerabilities)", user_input, re.IGNORECASE):
        return scan_own_website()

    response_text = handle_access_commands(user_input)
    if response_text:
        return response_text

    try:
        model = genai.GenerativeModel("gemini-2.0-flash")
        response = model.generate_content(AI_INSTRUCTIONS + "\n\nUser: " + user_input)
        return jsonify({"response": response.text})
    except Exception as e:
        return jsonify({"response": f"Error: {str(e)}"})

if __name__ == "__main__":
    app.run(debug=False)
