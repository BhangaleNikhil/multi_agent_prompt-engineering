# from src.tools.py_read import py_read

# print(py_read("./data/sample.py"))

from dotenv import load_dotenv
load_dotenv()

from src.graph.graph import graph_compilation

graph_compilation()