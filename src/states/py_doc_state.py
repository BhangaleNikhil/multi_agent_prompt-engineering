from typing import Optional, List, TypedDict

class PyDocState(TypedDict):
    count:int
    docs:Optional[List[str]]
    processed_docs:Optional[List[str]]
    docs_with_issues:Optional[List[str]]