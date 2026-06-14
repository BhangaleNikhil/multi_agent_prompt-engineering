from langchain.agents import create_agent
from src.tools.py_read import py_read
from src.config.config import Config
from src.states.app_state import AppState

config = Config()
def python_agent(state:AppState)->AppState:
    model = config.get_model()
    agent = create_agent(model=model,tools=[py_read])
    file_name = "./test_data/sample.py"
    result = agent.invoke({"messages": [{"role": "user", "content": f"Read the file {file_name} and find the issues with the code."}]})

    return state