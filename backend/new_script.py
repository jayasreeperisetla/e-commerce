import os
import subprocess
import json
import ast
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

# Configure Google Gemini model
chat = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.3)

MD_FILE = "test_description.md"
TEMPLATE_FILE = "prompt_template.txt"
PASSED_FILE = "test_passed1.py"
FAILED_FILE = "test_failed1.py"
TARGET_PASS_RATE = 90.0
MAX_ITERATIONS = 5

def read_file(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()

def validate_python(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError as e:
        print(f"⚠️ Generated code has syntax error: {e}")
        return False

def generate_pytest(md_content, template_content, feedback=""):
    prompt = template_content.replace("{test_description}", md_content)
    if feedback:
        prompt += f"\n\n# Feedback from previous run:\n{feedback}"

    response = chat.invoke([HumanMessage(content=prompt)])
    sanitized = re.sub(r"[^\x20-\x7E\n]", "", response.content)
    return sanitized

def save_pytest(content, output_file):
    if validate_python(content):
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"✅ File updated: {output_file}")
        return True
    else:
        print(f"🚫 Invalid Python detected in {output_file}. Keeping old file.")
        return False

def run_pytest(files):
    try:
        subprocess.run(
            ["pytest", *files, "--json-report", "--json-report-file=report.json"],
            capture_output=True,
            text=True,
        )

        if not os.path.exists("report.json"):
            print("⚠️ No pytest report.json found.")
            return 0.0, [], []

        with open("report.json", "r", encoding="utf-8") as f:
            report = json.load(f)

        summary = report.get("summary", {})
        total = summary.get("total", 0)
        passed = summary.get("passed", 0)
        pass_rate = (passed / total * 100) if total else 0.0

        failed_tests = []
        passed_tests = []
        for test in report.get("tests", []):
            nodeid = test.get("nodeid")
            if test.get("outcome") == "passed":
                passed_tests.append(nodeid)
            else:
                failed_tests.append(nodeid)

        return pass_rate, passed_tests, failed_tests

    except Exception as e:
        print("⚠️ Pytest execution issue:", e)
        return 0.0, [], []

def move_passing_tests(source_file, passed_tests):
    if not passed_tests:
        return

    # Extract only test function names from nodeids
    passed_names = set(t.split("::")[-1] for t in passed_tests)

    with open(source_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    failed_code = []
    passed_code = []
    current_test = []
    inside_test = False
    test_name = None
    indent_prefix = ""

    for line in lines:
        stripped = line.lstrip()
        # Detect function or method
        func_match = re.match(r"def (test_[\w_]+)\s*\(", stripped)
        if func_match:
            if inside_test:
                if test_name in passed_names:
                    passed_code.extend(current_test)
                else:
                    failed_code.extend(current_test)
            current_test = [line]
            inside_test = True
            test_name = func_match.group(1)
            indent_prefix = line[:len(line)-len(stripped)]
        elif inside_test:
            current_test.append(line)
        else:
            # Keep imports, fixtures, etc.
            failed_code.append(line)
            passed_code.append(line)

    # Add last test
    if current_test:
        if test_name in passed_names:
            passed_code.extend(current_test)
        else:
            failed_code.extend(current_test)

    # Append passed tests
    with open(PASSED_FILE, "a", encoding="utf-8") as f:
        f.writelines(passed_code)

    # Rewrite failed file
    with open(source_file, "w", encoding="utf-8") as f:
        f.writelines(failed_code)

    print(f"📦 Moved {len(passed_tests)} tests to {PASSED_FILE}:")
    for t in passed_tests:
        print(f"   ✅ {t}")

def auto_generate_tests(md_file, template_file, failed_file):
    md_content = read_file(md_file)
    template_content = read_file(template_file)
    feedback = ""

    # Reset files
    open(PASSED_FILE, "w").close()
    open(FAILED_FILE, "w").close()

    for iteration in range(1, MAX_ITERATIONS + 1):
        print(f"\n=== Iteration {iteration} ===")

        if not os.path.exists(FAILED_FILE) or os.stat(FAILED_FILE).st_size == 0:
            pytest_content = generate_pytest(md_content, template_content, feedback)
            if not save_pytest(pytest_content, failed_file):
                feedback += "\n⚠️ Previous generation produced invalid Python. Please fix."

        pass_rate, passed_tests, failed_tests = run_pytest([PASSED_FILE, FAILED_FILE])
        print(f"⚡ Pass rate: {pass_rate:.2f}%")

        if pass_rate >= TARGET_PASS_RATE:
            print("🎯 Target achieved! Stopping loop.")
            break

        if passed_tests:
            move_passing_tests(FAILED_FILE, passed_tests)

        if failed_tests:
            print(f"❌ Still failing tests ({len(failed_tests)}):")
            for t in failed_tests:
                print(f"   ❌ {t}")
            feedback = "The following tests failed:\n" + "\n".join(failed_tests)
            pytest_content = generate_pytest(md_content, template_content, feedback)
            if not save_pytest(pytest_content, FAILED_FILE):
                feedback += "\n⚠️ Last attempt had invalid Python syntax, please fix and retry."
        else:
            print("⚠️ No specific failing tests found, regenerating all...")
            pytest_content = generate_pytest(md_content, template_content, feedback)
            if not save_pytest(pytest_content, FAILED_FILE):
                feedback += "\n⚠️ Last regeneration produced invalid code, retrying..."

        print("📊 Iteration summary:")
        print(f"   ✅ Passed tests stored in {PASSED_FILE}")
        print(f"   ❌ Remaining failing tests in {FAILED_FILE}")

if __name__ == "__main__":
    auto_generate_tests(MD_FILE, TEMPLATE_FILE, FAILED_FILE)
