from langchain.agents import create_agent
from src.tools.dir_read import dir_structure
from src.config.config import Config
import json

config = Config()

def master_agent():
    model = config.get_model()
    agent = create_agent(model=model,tools=[dir_structure])

    dir_name = "./test_data"
    result = agent.invoke({"messages":[{"role": "user", "content": f"Read the directory {dir_name} and simply return all markdown file names in the directory."}]})
    return result