from src.config.config import Config
from langchain.agents import create_agent
from src.tools.dir_read import dir_structure
from src.states.app_state import AppState

config = Config()

def orchestrator(state:AppState) -> AppState:
    model = config.get_model()

    agent = create_agent(model=model,tools=[dir_structure])
    dir_name = "./test_data"
    result = agent.invoke({"messages":[{"role":"user","content":f"You are an orchestrator manager of ai workflow. you read the directory {dir_name}, then send python file names to python agent and once all file read calls master agent which reads all file and creates consolidated reports"}]})
    return state