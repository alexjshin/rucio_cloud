from typing import List

class RSE:
    def __init__(self, name: str, capacity: int):
        self.name = name
        self.capacity = capacity
        self.capacityLeft = capacity - sum([did.size for did in dids])
        self.capacityUsed = sum([did.size for did in dids])
        self.cloudCostModel = None