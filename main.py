from dotenv import load_dotenv
load_dotenv()

import os

root_path = os.getenv("ROOT_PATH","./")
base_storage_path = os.getenv("BASE_STORAGE_PATH","")
prompt_technique = os.getenv("PROMPT_TECHNIQUE","zero_shot")

import time
from src.config.config import Config
config = Config()

import logging
from src.utils import setup_logging
from src.graph.graph import graph_compilation

setup_logging()
logger = logging.getLogger(__name__)

storage = os.path.join(base_storage_path,prompt_technique)
graph_compilation(root_path=root_path,storage_folder=storage,prompt_technique=prompt_technique)