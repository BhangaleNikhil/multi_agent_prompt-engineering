from typing import TypedDict,List,Optional
from src.states.py_doc_state import PyDocState
from src.states.report_doc_state import ReportDocState

class AppState(TypedDict,total=False):
    root_path: Optional[str]
    py_docs: PyDocState
    reports: ReportDocState