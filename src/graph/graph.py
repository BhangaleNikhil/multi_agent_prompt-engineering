from langgraph.graph import StateGraph, START, END
from langchain.tools import tool_node
from src.states.app_state import AppState
from src.agents.orchestrator import orchestrator
from src.agents.python_agent import python_agent
from src.agents.master_agent import master_agent

def graph_compilation():
    graph = StateGraph(AppState)

    graph.add_node("orchestrator",orchestrator)
    graph.add_node("python_agent",python_agent)
    graph.add_node("master_agent",master_agent)

    graph.add_edge(START,"orchestrator")
    graph.add_edge("orchestrator","python_agent")
    graph.add_edge("python_agent","orchestrator")
    graph.add_edge("orchestrator","master_agent")
    graph.add_edge("master_agent",END)

    agent = graph.compile()
    agent.invoke({})
