from typing import Optional, List, TypedDict

class ReportDocState(TypedDict):
    count:int
    docs:List[str]
    processed_docs:Optional[List[str]]
    docs_with_issues:Optional[List[str]]