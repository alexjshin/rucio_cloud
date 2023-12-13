from rse import RSE
from typing import List, Tuple, Optional

class DID:
    def __init__(self, did: str, size: int, replicationRule: Tuple, rses: Optional[List[RSE]] = list(RSE)):
        self.did = did
        self.size = size
        self.replicationRule = replicationRule
        self.rses = rses
    
    def addRSE(self, rse: RSE):
        self.rses.append(rse)