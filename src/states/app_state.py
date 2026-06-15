from typing import TypedDict,List,Optional
from src.states.py_doc_state import PyDocState
from src.states.report_doc_state import ReportDocState

class AppState(TypedDict):
    root_path: str
    file_filter:str
    py_docs: PyDocState
    reports: ReportDocState