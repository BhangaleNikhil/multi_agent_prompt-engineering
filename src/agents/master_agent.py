from langchain.agents import create_agent
from src.tools.dir_read import get_relevant_file
from src.config.config import Config
from src.states.app_state import AppState
from src.utils import CacheHandler, LogCacheHandler, LogStorage
from langchain_text_splitters import RecursiveCharacterTextSplitter
from transformers import AutoTokenizer
from langchain_core.messages import message_to_dict
from datetime import datetime
import json, os
import logging

logger = logging.getLogger(__name__)
config = Config()

cache_handler = CacheHandler()
log_cache_handler = LogCacheHandler()
log_storage = LogStorage()

tokenizer = AutoTokenizer.from_pretrained("google/gemma-4-E4B-it")

def gemma_tokenizer(text:str) -> int:
    try:
        return len(tokenizer.encode(text, add_special_tokens=False))
    except Exception as e:
        logger.error(e)
        return 0

def master_agent(state:AppState) -> AppState:
    print(f"{'Master Agent':=^50}")
    try:
        model = config.get_model()
        agent = create_agent(model=model)

        prompt = state["prompts"].get("master_agent",config.get_master_prompt())
        cache_keys = state["reports"]["docs"]

        raw_context = ""
        results = ""

        for key in cache_keys:
            document = cache_handler.get_document(doc_key=key)
            file = document.get("file_path","")
            response = document.get("message","")

            final_response = f"File Path: {file}\n Reponse: {response}\n"
            raw_context += final_response

        raw_context += f"Following are the file where we had errors: {json.dumps(state["py_docs"]["docs_with_issues"])}"
        splitter = RecursiveCharacterTextSplitter(chunk_size=120000,chunk_overlap=100,length_function=gemma_tokenizer,separators=["\n\n","\n"])

        chunked_contexts = splitter.split_text(raw_context)
        logger.debug(f"Chunk list size: {len(chunked_contexts)}")

        for context in chunked_contexts:
            try:
                start = datetime.now()
                result = agent.invoke({"messages":[{"role": "user", "content": prompt.format(security_agent_reports=context,previous_report=results)}]})
                end = datetime.now()
                delta = end-start
                logger.debug(f"Time between agent execution: {delta}")
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
            except Exception as e:
                logger.error(e)
        
        content = f"{results}\n ## Python Agent Tokens:\n| Field | Value |\n|---|---|\n|Input Token Agent|{state["py_docs"]["input_tokens_agent"]}|\n|Output Token Agent|{state["py_docs"]["output_tokens_agent"]}|\n|Input Token Tool|{state["py_docs"]["input_tokens_tool"]}|\n|Output Token Tool|{state["py_docs"]["output_tokens_tool"]}|\n\n## Master Agent Tokens:\n| Field | Value |\n|---|---|\n|Input Token Agent|{state["reports"]["input_tokens_agent"]}|\n|Output Token Agent|{state["reports"]["output_tokens_agent"]}|\n|Input Token Tool|{state["reports"]["input_tokens_tool"]}|\n|Output Token Tool|{state["reports"]["output_tokens_tool"]}|"
        storage = state["storage_folder"]
        storage = os.path.join(os.path.abspath(storage),"master_report.md")
        try:
            with open (storage,"w+",encoding="utf-8") as file:
                file.write(content)
        except Exception as e:
            logger.error(e)

        logger.info("clearing documents for cache")
        start = datetime.now()
        for key in cache_keys:
            cache_handler.delete_document(doc_key=key)
        end = datetime.now()
        logger.info("cleared documents for cache")
        logger.info(f"Time taken to clear cache for documents: {end-start}")

        logger.info("Getting logs from cache")
        try:
            logs = [(log.get("timestamp",""),log.get("log_message","")) for log in log_cache_handler.get_logs(key="logs")]

            logger.info("Storing logs to long term storage")
            execution_status = log_storage.store_logs(logs=logs)
            logger.info("Stored logs to long term storage")
            if execution_status:
                logger.info("Deleting logs from cache")
                log_cache_handler.delete_all_logs(key="logs")
        except Exception as e:
            logger.error(e)    
    except Exception as e:
        logger.error(e)
    return state