# examples/statistics_test.py
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.capturer import PacketCapturer
from src.statistics import TrafficStatistics

def statistics_test():
    print("🧪 TRAFFIC STATISTICS TEST")
    
    # Create instances
    capturer = PacketCapturer(use_real_capture=True)
    stats_analyzer = TrafficStatistics()
    
    # Capture packets
    print("Capturing 10 packets for analysis...")
    capturer.start_capture(10)
    
    # Generate and display statistics
    print("\n" + "🔍 ANALYZING TRAFFIC PATTERNS...")
    statistics = stats_analyzer.generate_statistics(capturer.captured_packets)
    
    # Display the statistics
    stats_analyzer.display_statistics(statistics)
    
    print("🎉 Traffic statistics system working!")

if __name__ == "__main__":
    statistics_test()