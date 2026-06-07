from langchain.agents import create_agent
from langchain_ollama import ChatOllama
from src.tools.py_read import py_read
from dataclasses import dataclass

@dataclass
class Context:
    file_name:str

def python_agent():
    model = ChatOllama(model="gemma4:latest",temperature=0)
    agent = create_agent(model=model,tools=[py_read])
    file_name = "./test_data/sample.py"
    result = agent.invoke({"messages": [{"role": "user", "content": f"Read the file and find the issues with the code."}]},context=Context(file_name=file_name))

    return result