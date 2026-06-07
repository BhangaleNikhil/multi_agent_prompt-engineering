# from src.tools.py_read import py_read

# print(py_read("./data/sample.py"))

from src.agents.python_agent import python_agent
from src.agents.master_agent import master_agent
from src.agents.orchestrator import orchestrator
import json

print(orchestrator())