import os
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

def load_file(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

def save_file(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def generate_pytest(md_file, template_file, output_file):
    # Load files
    test_description = load_file(md_file)
    template = load_file(template_file)

    # Replace placeholder in prompt template
    prompt = template.replace("{test_description}", test_description)

    # Initialize Gemini (make sure GOOGLE_API_KEY is set in env)
    chat = ChatGoogleGenerativeAI(model="gemini-2.5-flash", temperature=0.3)

    # Call model
    response = chat.invoke([HumanMessage(content=prompt)])

    # Save pytest file
    save_file(output_file, response.content)
    print(f"✅ Pytest file generated: {output_file}")

if __name__ == "__main__":
    md_file = "test_description.md"
    template_file = "prompt_template.txt"
    output_file = "test_utils2.py"

    generate_pytest(md_file, template_file, output_file)
