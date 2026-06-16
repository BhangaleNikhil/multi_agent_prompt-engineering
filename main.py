# from src.tools.py_read import py_read

# print(py_read("./data/sample.py"))

from dotenv import load_dotenv
from src.graph.graph import graph_compilation
load_dotenv()

graph_compilation()