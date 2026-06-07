from src.config.config import Config
from langchain.agents import create_agent
from src.tools.dir_read import dir_structure

config = Config()

def orchestrator():
    model = config.get_model()

    agent = create_agent(model=model,tools=[dir_structure])
    result = agent.invoke({"messages":[{"role":"user","content":"You are an orchestrator manager of ai workflow. Tell me what are you going to do"}]})
    return result