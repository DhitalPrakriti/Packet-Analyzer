# examples/issue_detection_test.py
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.capturer import PacketCapturer
from src.detector import IssueDetector

def issue_detection_test():
    print("🧪 NETWORK ISSUE DETECTION TEST")
    
    # Create instances
    capturer = PacketCapturer(use_real_capture=True)
    detector = IssueDetector()
    
    # Capture packets
    print("Capturing 15 packets for issue analysis...")
    capturer.start_capture(15)
    
    # Analyze for issues
    print("\n🔍 ANALYZING FOR NETWORK ISSUES...")
    issues = detector.analyze_packets(capturer.captured_packets)
    
    # Display detected issues
    detector.display_issues()
    
    print("🎉 Issue detection system working!")

if __name__ == "__main__":
    issue_detection_test()