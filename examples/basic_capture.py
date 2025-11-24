# examples/basic_capture.py
import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.capturer import PacketCapturer
from src.parser import ProtocolParser

def test_parser():
    print("🧪 TEST 4 - Protocol Parsing & Educational Analysis")
    
    # Capture some packets
    capturer = PacketCapturer(use_real_capture=True)
    capturer.start_capture(2)
    
    # Parse them
    parser = ProtocolParser()
    
    print("\n📖 EDUCATIONAL ANALYSIS:")
    for i, packet in enumerate(capturer.captured_packets):
        print(f"\n--- Packet #{i+1} Analysis ---")
        analysis = parser.parse_packet(packet)
        
        print(f"Protocol: {analysis.get('protocol', 'Unknown')}")
        print(f"Summary: {analysis.get('summary', 'No analysis available')}")
        
        layers = analysis.get('layers', {})
        for layer_name, layer_info in layers.items():
            print(f"\n🔹 {layer_name.upper()} LAYER:")
            print(f"   Description: {layer_info.get('description', 'N/A')}")
            if 'educational_note' in layer_info:
                print(f"   💡 Educational Note: {layer_info['educational_note']}")
            
            # Show key fields
            for key, value in layer_info.items():
                if key not in ['description', 'educational_note']:
                    print(f"   {key}: {value}")

if __name__ == "__main__":
    test_parser()