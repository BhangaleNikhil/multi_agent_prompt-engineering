from dotenv import load_dotenv
load_dotenv()

import time
from src.config.config import Config
config = Config()

import logging
from src.utils import setup_logging
from src.graph.graph import graph_compilation

setup_logging()
logger = logging.getLogger(__name__)

execution_flow = [
    {
        "root_path":r"data\test_data",
        "storage_folder":r"reports\test_reports_storage\few_shot",
        "prompt_technique":"few_shot"
    },
    {
        "root_path":r"data\test_data",
        "storage_folder":r"reports\test_reports_storage\zero_shot",
        "prompt_technique":"zero_shot"
    },
    {
        "root_path":r"data\test_data",
        "storage_folder":r"reports\test_reports_storage\chain_of_thought",
        "prompt_technique":"chain_of_thought"
    },
    {
        "root_path":r"data\test_data",
        "storage_folder":r"reports\test_reports_storage\structured_output",
        "prompt_technique":"structured_output"
    },
    {
        "root_path":r"data\test_data",
        "storage_folder":r"reports\test_reports_storage\role_based",
        "prompt_technique":"role_based"
    }

]

# for flow in execution_flow:
#     print(flow)
graph_compilation(**execution_flow[0])
time.sleep(120)