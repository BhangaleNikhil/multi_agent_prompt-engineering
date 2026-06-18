from langchain.agents import create_agent
from src.tools.dir_read import get_relevant_file
from src.config.config import Config
from src.states.app_state import AppState
from src.utils import CacheHandler
from langchain_text_splitters import RecursiveCharacterTextSplitter
from transformers import AutoTokenizer
from langchain_core.messages import message_to_dict
import json, os

config = Config()

cache_handler = CacheHandler()

tokenizer = AutoTokenizer.from_pretrained("google/gemma-4-E4B-it")

def gemma_tokenizer(text:str) -> int:
    return len(tokenizer.encode(text, add_special_tokens=False))

def master_agent(state:AppState) -> AppState:
    print(f"{'Master Agent':=^50}")
    model = config.get_model()
    agent = create_agent(model=model)

    prompt = config.get_master_prompt()
    cache_keys = state["reports"]["docs"]

    raw_context = ""
    results = ""

    for key in cache_keys:
        document = cache_handler.get_document(doc_key=key)
        file = document.get("file_path","")
        response = document.get("message","")

        final_response = f"{file}\n{response}\n"
        raw_context += final_response

    raw_context += f"Following are the file where we had errors: {json.dumps(state["py_docs"]["docs_with_issues"])}"
    splitter = RecursiveCharacterTextSplitter(chunk_size=120000,chunk_overlap=100,length_function=gemma_tokenizer,separators=["\n\n","\n"])

    chunked_contexts = splitter.split_text(raw_context)

    for context in chunked_contexts:
        result = agent.invoke({"messages":[{"role": "user", "content": prompt.format(security_agent_reports=context,previous_report=results)}]})
        
        messages = result.get("messages", [])

        serializable_messages = [message_to_dict(msg) for msg in messages]

        ai_response = ""
        for msg in serializable_messages:
            if msg["type"]=="ai" and msg["data"]["content"]:
                ai_response = msg["data"]["content"]
                state["reports"]["input_tokens_agent"] += msg["data"]["usage_metadata"]["input_tokens"]
                state["reports"]["output_tokens_agent"] += msg["data"]["usage_metadata"]["output_tokens"]
            elif msg["type"]=="ai" and msg["data"]["tool_calls"]:
                state["reports"]["input_tokens_tool"] += msg["data"]["usage_metadata"]["input_tokens"]
                state["reports"]["output_tokens_tool"] += msg["data"]["usage_metadata"]["output_tokens"]

        results=ai_response
    
    content = f"{results}\n ## Python Agent Tokens:\n| Field | Value |\n|---|---|\n|Input Token Agent|{state["py_docs"]["input_tokens_agent"]}|\n|Output Token Agent|{state["py_docs"]["output_tokens_agent"]}|\n|Input Token Tool|{state["py_docs"]["input_tokens_tool"]}|\n|Output Token Tool|{state["py_docs"]["output_tokens_tool"]}|\n\n## Master Agent Tokens:\n| Field | Value |\n|---|---|\n|Input Token Agent|{state["reports"]["input_tokens_agent"]}|\n|Output Token Agent|{state["reports"]["output_tokens_agent"]}|\n|Input Token Tool|{state["reports"]["input_tokens_tool"]}|\n|Output Token Tool|{state["reports"]["output_tokens_tool"]}|"
    storage = state["storage_folder"]
    storage = os.path.join(os.path.abspath(storage),"master_report.md")
    with open (storage,"w+",encoding="utf-8") as file:
        file.write(content)
    return state