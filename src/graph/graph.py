from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from src.states import AppState, PyDocState, ReportDocState
from src.agents import orchestrator,master_agent,python_agent

from src.tools import orchestrator_tools, python_tools

def graph_compilation():
    graph = StateGraph(AppState)

    graph.add_node("orchestrator",orchestrator)
    graph.add_node("python_agent",python_agent)
    graph.add_node("master_agent",master_agent)

    orchestrator_tools_node = ToolNode(tools=orchestrator_tools)
    graph.add_node("orchestrator_tools",orchestrator_tools_node)
    python_tools_node = ToolNode(tools=python_tools)
    graph.add_node("python_tools",python_tools_node)

    graph.add_edge(START,"orchestrator")
    graph.add_edge("orchestrator","python_agent")
    graph.add_edge("python_agent","orchestrator")
    graph.add_edge("orchestrator","master_agent")

    graph.add_edge("orchestrator","orchestrator_tools")
    graph.add_edge("orchestrator_tools","orchestrator")
    graph.add_edge("python_agent","python_tools")
    graph.add_edge("python_tools","python_agent")

    graph.add_edge("master_agent",END)

    agent = graph.compile()
    python_state = PyDocState({"count":None,"docs":None,"processed_docs":None,"docs_with_issues":None})
    report_state = ReportDocState({"count":None,"docs":None,"docs_with_issues":None,"processed_docs":None})
    state = AppState({"root_path":"./test_data","py_docs":python_state,"reports":report_state})
    
    agent.invoke(state)
