from typing import Optional, List, TypedDict

class ReportDocState(TypedDict):
    count:int
    docs:List[str]
    processed_docs:Optional[List[str]]
    docs_with_issues:Optional[List[str]]
    input_tokens_tool:int
    output_tokens_tool:int
    input_tokens_agent:int
    output_tokens_agent:int