from src.states import AppState

def orchestrator(state:AppState)->AppState:
    py_doc_count = state["py_docs"]["count"]
    py_files = state["py_docs"]["docs"]
    reports = state["reports"]["docs"]
    if not py_doc_count and not py_files:
        state["file_filter"] = "python"
    elif py_doc_count and (not py_files and reports):
        state["file_filter"] = "master"
    return state