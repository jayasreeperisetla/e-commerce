import os
import ast
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.prompts import ChatPromptTemplate

def load_source_code(source_folder):
    """Recursively loads all source code from the source folder."""
    code_files = {}
    for root, _, files in os.walk(source_folder):
        for file in files:
            if file.endswith(".py"):  # assuming Python-only
                full_path = os.path.join(root, file)
                with open(full_path, "r", encoding="utf-8") as f:
                    code_files[full_path] = f.read()
    return code_files

def extract_functions(code_files, functions_to_find):
    """Extract specific function definitions using AST parsing."""
    extracted = {}
    for path, code in code_files.items():
        if not path.endswith(".py"):
            continue
        try:
            tree = ast.parse(code)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in functions_to_find:
                start_line = node.lineno - 1
                end_line = node.end_lineno
                func_code = "\n".join(code.splitlines()[start_line:end_line])
                extracted[node.name] = {"file": path, "code": func_code}
    return extracted

def generate_tests(extracted_functions, output_file, model="gemini-1.5-flash"):
    """Generates test cases using LangChain + Gemini Pro with dependency hints."""
    chat = ChatGoogleGenerativeAI(model=model, temperature=0.3)

    template = ChatPromptTemplate.from_messages([
    ("system", "You are an expert software test engineer."),
    ("human", """
You are given the following **source code** (functions, classes, or methods) extracted from a project:

{functions_code}

Generate **high-quality pytest-style test case descriptions** in Markdown.

# Output Format
- Return **only Markdown**, nothing else.
- For each function/class/method, use this structure:

  ### Function: <function_name>
  - **Test Case 1 (Positive):** <clear, deterministic description>
  - **Test Case 2 (Negative):** <clear, deterministic description>
  - **Test Case 3 (Edge):** <clear, deterministic description>
  ...

# Requirements
- **7-10 test cases per function/class/method.**
- Cover:
  - Positive paths (expected behavior).
  - Negative paths (invalid input, bad state).
  - Edge cases (boundary values, unusual inputs).
  - Exception handling (dependencies raise errors).
  - Unusual system conditions (timeouts, empty values).
- Be **deterministic**:
  - Explicitly state expected outcome (e.g., *raises `HTTPException(status_code=400, detail="Invalid email")`*).
  - Specify whether mocks are **called once, not called, or multiple times**.
- **Always mock external dependencies**:
  - Database (e.g., queries, persistence).
  - Network, email, file I/O, or external APIs.
- Assume all imports/dependencies exist exactly as shown in the code.
- The descriptions must be **ready to translate into runnable pytest code** without guessing.
"""),
])



    # 🔹 Build the functions string with explicit Dependencies section
    functions_code_str = ""
    for func, data in extracted_functions.items():
        lines = data["code"].splitlines()
        import_lines = [l for l in lines if l.startswith("import ") or l.startswith("from ")]
        func_lines = [l for l in lines if not (l.startswith("import ") or l.startswith("from "))]

        imports_block = "\n".join(import_lines)
        func_block = "\n".join(func_lines)

        functions_code_str += f"\n### Function: {func} (from {data['file']})\n"
        functions_code_str += f"**Dependencies:**\n```python\n{imports_block}\n```\n"
        functions_code_str += f"**Function Code:**\n```python\n{func_block}\n```\n"

    messages = template.format_messages(functions_code=functions_code_str)
    response = chat.invoke(messages)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(response.content)

    print(f"✅ Test description saved to {output_file}")


if __name__ == "__main__":
    # 🔹 Hardcode your inputs here
    source_folder = "."  # your project folder
    functions = ["generate_email_reset_password", "create_user", "send_email"]
    output_file = "test_description.md"

    # Run pipeline
    code_files = load_source_code(source_folder)
    extracted = extract_functions(code_files, functions)

    if not extracted:
        print("❌ No matching functions found.")
    else:
        generate_tests(extracted, output_file)
