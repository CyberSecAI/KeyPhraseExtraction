import os

#A general-purpose script that converts .ipynb to .py
script_content = ""
import sys
import os
from nbconvert import PythonExporter
import nbformat

def convert_notebook_to_script(notebook_path):
    if not notebook_path.endswith(".ipynb"):
        print("Error: Input file must be a .ipynb file.")
        return

    try:
        with open(notebook_path, "r", encoding="utf-8") as f:
            notebook = nbformat.read(f, as_version=4)

        exporter = PythonExporter()
        python_code, _ = exporter.from_notebook_node(notebook)

        script_path = os.path.splitext(notebook_path)[0] + ".py"
        with open(script_path, "w", encoding="utf-8") as f:
            f.write(python_code)

        print(f"Converted to: {script_path}")
    except Exception as e:
        print(f"Error during conversion: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python convert_ipynb.py <notebook_file.ipynb>")
    else:
        convert_notebook_to_script(sys.argv[1])

