import os
from pathlib import Path
from typing import Dict,Any

class Utilities:
    def __init__(self):
        pass

    def exists(self, file_path:str)->bool:
        file_path = file_path.strip()
        if file_path:
            return os.path.exists(file_path)
        else:
            return False
        
    def get_dir_structure(self,root_dir_path:str):
        structure :Dict[str,Any] = {}
        for element in os.listdir(root_dir_path):
            element_path = os.path.join(root_dir_path,element)
            if element not in ["__pycache__"]:
                if os.path.isdir(element_path):
                    structure[element] = self.get_dir_structure(element_path)
                else:
                    structure[element] = None

        return structure