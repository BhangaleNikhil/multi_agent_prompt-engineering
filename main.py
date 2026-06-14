# from src.tools.py_read import py_read

# print(py_read("./data/sample.py"))

# from src.graph.graph import graph_compilation

# graph_compilation()

from src.tools.dir_read import get_dir_structure

print(get_dir_structure.invoke({"root_dir_path":"./test_data"}))