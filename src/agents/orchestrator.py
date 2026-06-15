from src.states import AppState

def orchestrator(state:AppState)->AppState:
    py_doc_count = state["py_docs"]["count"]
    py_files = state["py_docs"]["docs"]
    if not py_doc_count and not py_files:
        state["file_filter"] = "python"
    return state