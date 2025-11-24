
__version__ = "1.0.0"
__author__ = "Prakriti Dhital" 
__description__ = "Educational Network Packet Analyzer"

def __init__(self):
    self.capturer = None
    self.parser = ProtocolParser()
    self.filters = PacketFilter()
    self.stats = TrafficStatistics()
    self.detector = IssueDetector()
    self.storage = PacketStorage()  # Add this lines