from dotenv import load_dotenv
load_dotenv()

from src.graph.graph import graph_compilation

graph_compilation(root_path=r".\test_data",storage_folder=r"test_data\test_reports",prompt_technique="chain_of_thought")