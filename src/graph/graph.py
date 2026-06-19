from langgraph.graph import StateGraph, START, END
from langgraph.prebuilt import ToolNode
from src.states import AppState, PyDocState, ReportDocState
from src.agents import orchestrator_router,master_agent,python_agent, orchestrator,report_writer

import logging
logger = logging.getLogger(__name__)

from src.tools import  python_tools, get_relevant_file

def graph_compilation(root_path:str,storage_folder:str,prompt_technique:str):
    try:
        graph = StateGraph(AppState)
        graph.add_node("python_agent",python_agent)
        graph.add_node("master_agent",master_agent)
        graph.add_node("get_relevant_files",get_relevant_file)
        graph.add_node("orchestrator",orchestrator)
        graph.add_node("report_writer",report_writer)

        route_map = ["get_relevant_files",
                    "python_agent","master_agent","report_writer"]
        
        graph.set_entry_point("orchestrator")
        graph.add_edge("python_agent","orchestrator")
        graph.add_edge("get_relevant_files","orchestrator")
        graph.add_edge("report_writer","orchestrator")
        graph.add_conditional_edges("orchestrator",orchestrator_router,path_map=route_map)
        
        graph.add_edge("master_agent",END)

        agent = graph.compile()
        python_state = PyDocState({"count":None,"docs":None,"processed_docs":[],"docs_with_issues":[],"input_tokens_agent":0,"output_tokens_agent":0,"input_tokens_tool":0,"output_tokens_tool":0})
        report_state = ReportDocState({"count":0,"docs":[],"docs_with_issues":None,"processed_docs":None,"input_tokens_agent":0,"output_tokens_agent":0,"input_tokens_tool":0,"output_tokens_tool":0})
        state = AppState({"root_path":root_path,"file_filter":"","cache_key":[],"py_docs":python_state,"reports":report_state,"storage_folder":storage_folder,"prompt_technique":prompt_technique,"prompts":{"":""}})
        
        agent.invoke(state)
    except Exception as e:
        logger.error(e)