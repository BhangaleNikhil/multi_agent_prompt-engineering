from langchain.agents import create_agent
from src.tools.py_read import py_read
from src.config.config import Config
from src.states.app_state import AppState
from langchain_core.messages import message_to_dict
from langchain_text_splitters import RecursiveCharacterTextSplitter, Language
from transformers import AutoTokenizer
from src.utils import CacheHandler
from typing import List
import json
import os
from datetime import datetime
import logging
logger = logging.getLogger(__name__)

cache_handler = CacheHandler()
tokenizer = AutoTokenizer.from_pretrained("google/gemma-4-E4B-it")
config = Config()
tokenizer = AutoTokenizer.from_pretrained("google/gemma-4-E4B-it")

def gemma_tokenizer(code:str) -> int:
    try:
        return len(tokenizer.encode(code, add_special_tokens=False))
    except Exception as e:
        logger.error(e)
        return 0

def chunk_code(code)->List:
    try:
        splitter = RecursiveCharacterTextSplitter.from_language(language=Language.PYTHON, chunk_size=120000,chunk_overlap=100,length_function=gemma_tokenizer)
        chunks = splitter.split_text(code)
        return chunks
    except Exception as e:
        logger.error(e)
        return []

def python_agent(state:AppState)->AppState:
    file_path = state["py_docs"]["docs"].pop() if state["py_docs"]["docs"] else "there is no file"
    try:
        model = config.get_model()
        agent = create_agent(model=model,tools=[])

        # For caching reports
        file_name = file_path.split(os.path.sep)[-1]
        timestamp = datetime.now().strftime("%d%m%Y_%H%M%S")
        doc_id = f"{file_name}:{timestamp}"

        prompt = state["prompts"].get("python_agent",config.get_python_prompt())

        code = py_read(file_path)

        chunks = chunk_code(code)
        logger.debug(f"Chunk list size: {len(chunks)}")
        report = ""
        for chunk in chunks:
            try:
                start = datetime.now()
                result = agent.invoke({"messages": [{"role": "user", "content": prompt.format(code=chunk,previous_report=report)}]})
                end = datetime.now()
                delta = end-start
                logger.debug(f"Time between agent execution: {delta}")

                messages = result.get("messages", [])

                serializable_messages = [message_to_dict(msg) for msg in messages]

                ai_response = ""
                for msg in serializable_messages:
                    if msg["type"]=="ai" and msg["data"]["content"]:
                        ai_response = msg["data"]["content"]
                        state["py_docs"]["input_tokens_agent"] += msg["data"]["usage_metadata"]["input_tokens"]
                        state["py_docs"]["output_tokens_agent"] += msg["data"]["usage_metadata"]["output_tokens"]
                    elif msg["type"]=="ai" and msg["data"]["tool_calls"]:
                        state["py_docs"]["input_tokens_tool"] += msg["data"]["usage_metadata"]["input_tokens"]
                        state["py_docs"]["output_tokens_tool"] += msg["data"]["usage_metadata"]["output_tokens"]
                report = ai_response
            except Exception as e:
                logger.error(e)

        response = {"message": report, "file_path":file_path }

        state["py_docs"]["processed_docs"].append(file_path)

        doc_key = cache_handler.save_document(doc_id=doc_id,document=response)
        doc_key = cache_handler._get_doc_key(doc_id)
        print(doc_key)
        state["cache_key"].append(doc_key)
    except Exception as e:
        logger.error(e)
        state["py_docs"]["docs_with_issues"].append(json.dumps({"file":file_path,"error":e}))

    return state