# src/cli.py
import argparse
import sys
import os

# Add the parent directory to Python path so we can import from src
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Now import from the src package
from src.capturer import PacketCapturer
from src.parser import ProtocolParser
from src.filters import PacketFilter
from src.statistics import TrafficStatistics
from src.detector import IssueDetector
from src.storage import PacketStorage

class PacketAnalyzerCLI:
    """
    Main Command Line Interface for the Packet Analyzer
    Educational tool for network protocol analysis
    """
    
    def __init__(self):
        self.capturer = None
        self.parser = ProtocolParser()
        self.filters = PacketFilter()
        self.stats = TrafficStatistics()
        self.detector = IssueDetector()
        self.storage = PacketStorage() 
        
    def run(self):
        """Main CLI entry point"""
        parser = argparse.ArgumentParser(
            description='Educational Network Packet Analyzer - Understand networking through packet analysis',
            epilog='''
Examples:
  python src/cli.py --demo                    # Run demo with all features
  python src/cli.py --capture --count 10      # Capture 10 packets
  python src/cli.py --capture --stats         # Capture and show statistics
  python src/cli.py --capture --analyze       # Capture and analyze packets
  python src/cli.py --load capture.json --stats --detect-issues  # Load and analyze saved capture
            '''
        )
        
        # Main action options
        parser.add_argument('--demo', action='store_true', 
                          help='Run complete demo (capture, analyze, stats, detect issues)')
        parser.add_argument('--capture', action='store_true', 
                          help='Capture packets')
        
        # Capture options
        parser.add_argument('--count', type=int, default=10, 
                          help='Number of packets to capture (default: 10)')
        parser.add_argument('--timeout', type=int, default=30, 
                          help='Capture timeout in seconds (default: 30)')
        parser.add_argument('--interface', type=str, 
                          help='Network interface to use')
        
        # Analysis options
        parser.add_argument('--analyze', action='store_true', 
                          help='Analyze captured packets')
        parser.add_argument('--stats', action='store_true', 
                          help='Show traffic statistics')
        parser.add_argument('--detect-issues', action='store_true', 
                          help='Detect network issues')
        parser.add_argument('--parse-all', action='store_true', 
                          help='Parse all captured packets')
        
        # Filter options
        parser.add_argument('--filter-protocol', type=str, 
                          help='Filter by protocol (TCP, UDP, ICMP, etc.)')
        parser.add_argument('--filter-src-ip', type=str, 
                          help='Filter by source IP')
        parser.add_argument('--filter-dst-ip', type=str, 
                          help='Filter by destination IP')
        
        # Storage options
        parser.add_argument('--save', type=str, 
                  help='Save capture to file (provide filename)')
        parser.add_argument('--save-format', choices=['json', 'pkl'], default='json',
                  help='File format for saving (default: json)')
        parser.add_argument('--load', type=str,
                  help='Load capture from file')
        parser.add_argument('--list-captures', action='store_true',
                  help='List all saved captures')
        parser.add_argument('--delete-capture', type=str,
                  help='Delete a capture file')
        
        args = parser.parse_args()
        
        print("🚀 Educational Packet Analyzer - Starting...")
        print("=" * 60)
        
        # If no arguments provided, show help and run demo
        if not any(vars(args).values()):
            print("🤔 No arguments provided. Running demo mode...")
            args.demo = True
        
        # Run demo mode (comprehensive analysis)
        if args.demo:
            self.run_demo()
            return
        
        # Handle packet loading first
        packets_loaded = False
        if args.load:
            packets_loaded = self.load_capture(args)

        # Capture packets if requested (and no packets loaded)
        if args.capture and not packets_loaded:
            self.capture_packets(args)
        elif not packets_loaded:
            # If no capture but analysis requested, and no packets loaded, we need packets
            if any([args.analyze, args.stats, args.detect_issues, args.parse_all]):
                print("📡 No packets captured yet. Capturing 10 packets for analysis...")
                self.capture_packets(args)
        
        # Apply filters if specified
        if any([args.filter_protocol, args.filter_src_ip, args.filter_dst_ip]):
            self.apply_filters(args)
        
        # Perform analysis if requested
        if args.analyze:
            self.analyze_packets(args)
        
        if args.stats:
            self.show_statistics()
        
        if args.detect_issues:
            self.detect_issues()
            
        if args.save:
            self.save_capture(args)

        if args.list_captures:
            self.list_captures()

        if args.delete_capture:
            self.delete_capture(args)
        
        if args.parse_all:
            self.parse_all_packets()
        
        print("=" * 60)
        print("✅ Packet analysis completed!")
    
    def run_demo(self):
        """Run a comprehensive demo of all features"""
        print("🎯 RUNNING COMPREHENSIVE DEMO")
        print("This will demonstrate all features of the packet analyzer")
        
        # Capture packets
        print(f"\n📡 CAPTURING 8 PACKETS...")
        self.capturer = PacketCapturer(use_real_capture=True)
        self.capturer.start_capture(8, 20)  # 8 packets, 20 second timeout
        
        if not self.capturer.captured_packets:
            print("❌ No packets captured in demo")
            return
        
        print(f"✅ Captured {len(self.capturer.captured_packets)} packets")
        
        # Show statistics
        self.show_statistics()
        
        # Detect issues
        self.detect_issues()
        
        # Analyze first 2 packets
        print(f"\n🔬 ANALYZING FIRST 2 PACKETS IN DETAIL...")
        for i, packet in enumerate(self.capturer.captured_packets[:2]):
            print(f"\n--- Packet #{i+1} Detailed Analysis ---")
            analysis = self.parser.parse_packet(packet)
            
            print(f"Protocol: {analysis.get('protocol', 'Unknown')}")
            print(f"Summary: {analysis.get('summary', 'No analysis available')}")
            
            layers = analysis.get('layers', {})
            for layer_name, layer_info in layers.items():
                print(f"🔹 {layer_name.upper()} LAYER:")
                print(f"   Description: {layer_info.get('description', 'N/A')}")
                if 'educational_note' in layer_info:
                    print(f"   💡 {layer_info['educational_note']}")
    
    def capture_packets(self, args):
        """Capture packets based on CLI arguments"""
        print(f"\n📡 CAPTURING {args.count} PACKETS...")
        self.capturer = PacketCapturer(use_real_capture=True)
        self.capturer.start_capture(args.count, args.timeout)
        
        if self.capturer.captured_packets:
            print(f"✅ Successfully captured {len(self.capturer.captured_packets)} packets")
        else:
            print("❌ No packets captured")
    
    def apply_filters(self, args):
        """Apply filters based on CLI arguments"""
        if not self.capturer or not self.capturer.captured_packets:
            print("❌ No packets available for filtering")
            return
        
        print(f"\n🔍 APPLYING FILTERS...")
        
        if args.filter_protocol:
            self.filters.add_protocol_filter(args.filter_protocol.upper())
        
        if args.filter_src_ip or args.filter_dst_ip:
            self.filters.add_ip_filter(args.filter_src_ip, args.filter_dst_ip)
        
        filtered_packets = self.filters.apply_filters(self.capturer.captured_packets)
        
        if filtered_packets:
            print(f"📦 FILTERED PACKETS ({len(filtered_packets)}):")
            for packet in filtered_packets[:5]:  # Show first 5
                print(f"   #{packet['number']}: {packet['protocol']} - {packet['summary']}")
            if len(filtered_packets) > 5:
                print(f"   ... and {len(filtered_packets) - 5} more")
        else:
            print("❌ No packets match the filters")
    
    def analyze_packets(self, args):
        """Analyze captured packets"""
        if not self.capturer or not self.capturer.captured_packets:
            print("❌ No packets available for analysis")
            return
        
        print(f"\n🔬 ANALYZING PACKETS...")
        
        # Analyze first 3 packets in detail
        for i, packet in enumerate(self.capturer.captured_packets[:3]):
            print(f"\n--- Packet #{i+1} Detailed Analysis ---")
            analysis = self.parser.parse_packet(packet)
            
            print(f"Protocol: {analysis.get('protocol', 'Unknown')}")
            print(f"Summary: {analysis.get('summary', 'No analysis available')}")
            
            layers = analysis.get('layers', {})
            for layer_name, layer_info in layers.items():
                print(f"🔹 {layer_name.upper()} LAYER:")
                print(f"   Description: {layer_info.get('description', 'N/A')}")
                if 'educational_note' in layer_info:
                    print(f"   💡 {layer_info['educational_note']}")
    
    def show_statistics(self):
        """Show traffic statistics"""
        if not self.capturer or not self.capturer.captured_packets:
            print("❌ No packets available for statistics")
            return
        
        print(f"\n📊 GENERATING TRAFFIC STATISTICS...")
        statistics = self.stats.generate_statistics(self.capturer.captured_packets)
        self.stats.display_statistics(statistics)
    
    def detect_issues(self):
        """Detect network issues"""
        if not self.capturer or not self.capturer.captured_packets:
            print("❌ No packets available for issue detection")
            return
        
        print(f"\n🚨 DETECTING NETWORK ISSUES...")
        issues = self.detector.analyze_packets(self.capturer.captured_packets)
        self.detector.display_issues()
        
    def save_capture(self, args):
        """Save captured packets to file"""
        if not self.capturer or not self.capturer.captured_packets:
            print("❌ No packets available to save")
            return
    
        self.storage.save_capture(
            self.capturer.captured_packets, 
            args.save, 
            args.save_format
        )

    def load_capture(self, args):
        """Load packets from file"""
        packets = self.storage.load_capture(args.load)
        if packets:
            # Create a new capturer instance and load the packets
            self.capturer = PacketCapturer()
            self.capturer.captured_packets = packets
            self.capturer.packet_count = len(packets)
            print(f"✅ Loaded {len(packets)} packets into analyzer")
            
            return True
        return False

    def list_captures(self):
        """List all saved captures"""
        self.storage.list_captures()

    def delete_capture(self, args):
        """Delete a capture file"""
        self.storage.delete_capture(args.delete_capture)
        
    def parse_all_packets(self):
        """Parse all captured packets"""
        if not self.capturer or not self.capturer.captured_packets:
            print("❌ No packets available for parsing")
            return
        
        print(f"\n📖 PARSING ALL {len(self.capturer.captured_packets)} PACKETS...")
        
        protocol_count = {}
        for packet in self.capturer.captured_packets:
            protocol = packet.get('protocol', 'Unknown')
            protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
        
        print("📋 PROTOCOL SUMMARY:")
        for protocol, count in protocol_count.items():
            percentage = (count / len(self.capturer.captured_packets)) * 100
            print(f"   {protocol}: {count} packets ({percentage:.1f}%)")

def main():
    """Main function"""
    try:
        cli = PacketAnalyzerCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\n⏹️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()