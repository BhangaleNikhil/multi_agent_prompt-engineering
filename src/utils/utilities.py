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