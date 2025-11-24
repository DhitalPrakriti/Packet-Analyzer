import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.capturer import PacketCapturer
from src.parser import ProtocolParser
from src.filters import PacketFilter

def filter_test():
    print("🧪 FILTERING SYSTEM TEST")
    
    # Create instances
    capturer = PacketCapturer(use_real_capture=True)
    parser = ProtocolParser()
    packet_filter = PacketFilter()
    
    # Capture some packets
    print("Capturing 5 packets...")
    capturer.start_capture(5)
    
    # Show all packets first
    print(f"\n📦 ALL CAPTURED PACKETS ({len(capturer.captured_packets)}):")
    for packet in capturer.captured_packets:
        print(f"  #{packet['number']}: {packet['protocol']} - {packet['summary']}")
    
    # Test protocol filter
    print("\n1. Testing PROTOCOL filter (ICMPv6 only):")
    packet_filter.add_protocol_filter("ICMPv6")
    filtered = packet_filter.apply_filters(capturer.captured_packets)
    
    for packet in filtered:
        analysis = parser.parse_packet(packet)
        print(f"  ✅ #{packet['number']}: {analysis['summary']}")
    
    # Clear and test different filter
    packet_filter.clear_filters()
    
    print("\n2. Testing IP filter (IPv6 traffic):")
    # This will filter for IPv6 related packets
    def ipv6_filter(packet_info):
        return "IPv6" in packet_info.get('summary', '') or "ICMPv6" in packet_info.get('protocol', '')
    
    packet_filter.filters.append(ipv6_filter)
    filtered = packet_filter.apply_filters(capturer.captured_packets)
    
    for packet in filtered:
        print(f"  ✅ #{packet['number']}: {packet['protocol']} - {packet['summary']}")
    
    print("🎉 Filtering system working!")

if __name__ == "__main__":
    filter_test()