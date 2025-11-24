# src/capturer.py
import time
import random

class PacketCapturer:
    """
    Packet capturer with real Scapy capability and simulation fallback
    """
    
    def __init__(self, use_real_capture=False):
        self.captured_packets = []
        self.use_real_capture = use_real_capture
        self.scapy_available = self._check_scapy()
        
        print("✅ PacketCapturer created!")
        if self.scapy_available and use_real_capture:
            print("🔍 Real packet capture enabled")
        else:
            print("💡 Simulation mode (safe for development)")
    
    def _check_scapy(self):
        """Check if Scapy is available"""
        try:
            import scapy.all
            return True
        except ImportError:
            return False
    
    def start_capture(self, count=5, timeout=30):
        """Start packet capture - real or simulated"""
        if self.use_real_capture and self.scapy_available:
            self._real_capture(count,timeout)
        else:
            self._simulated_capture(count,timeout)
    
    def _real_capture(self, count,timeout=30):
        """Real packet capture using Scapy"""
        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            
            print(f"🎯 Capturing {count} REAL packets (timeout: {timeout}...")
            
            packets_captured = 0
            
            def process_packet(packet):
                nonlocal packets_captured
                packets_captured += 1
                
                # Detect protocol from real packet
                protocol = self._detect_protocol(packet)
                
                packet_info = {
                    'number': packets_captured,
                    'timestamp': time.time(),
                    'length': len(packet),
                    'protocol': protocol,
                    'summary': packet.summary(),
                    'real_packet': True,
                    'raw_packet': packet 
                }
                self.captured_packets.append(packet_info)
                print(f"📦 #{packet_info['number']}: {protocol} - {packet.summary()}")
                
                if packets_captured >= count:
                    return True  # Stop capture
                return False
            
            scapy.sniff(count=count, prn=process_packet, timeout=10)
            print("✅ Real capture completed!")
            
        except Exception as e:
            print(f"❌ Real capture failed: {e}")
            print("🔄 Falling back to simulation...")
            self._simulated_capture(count)
    
    def _detect_protocol(self, packet):
        """Detect protocol from real Scapy packet - IMPROVED VERSION"""
        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            
            if packet.haslayer(TCP):
                return "TCP"
            elif packet.haslayer(UDP):
                return "UDP" 
            elif packet.haslayer(ICMP):
                return "ICMP"
            elif packet.haslayer(IPv6):
                # Check for ICMPv6
                if packet.haslayer(scapy.ICMPv6ND_RA) or packet.haslayer(scapy.ICMPv6MLReport2):
                    return "ICMPv6"
                return "IPv6"
            elif packet.haslayer(IP):
                return "IP"
            elif packet.haslayer(scapy.ARP):
                return "ARP"
            elif packet.haslayer(scapy.DNS):
                return "DNS"
            elif packet.haslayer(scapy.DHCP):
                return "DHCP"
            else:
                # Try to get protocol from summary
                summary = packet.summary()
                if 'TCP' in summary:
                    return "TCP"
                elif 'UDP' in summary:
                    return "UDP"
                elif 'DNS' in summary:
                    return "DNS"
                elif 'HTTP' in summary:
                    return "HTTP"
                else:
                    return "Other"
        except:
            return "Unknown"
    
    def _simulated_capture(self, count):
        """Simulated packet capture"""
        print(f"🎯 Simulating capture of {count} packets...")
        
        protocols = ['TCP', 'UDP', 'HTTP', 'DNS', 'ICMP']
        source_ips = ['192.168.1.100', '10.0.0.5', '172.16.0.10']
        dest_ips = ['8.8.8.8', '93.184.216.34', '151.101.1.69']
        
        for i in range(count):
            protocol = random.choice(protocols)
            src_ip = random.choice(source_ips)
            dst_ip = random.choice(dest_ips)
            
            packet_info = {
                'number': i + 1,
                'timestamp': time.time(),
                'length': random.randint(60, 1500),
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'summary': f"{protocol} {src_ip} → {dst_ip}",
                'real_packet': False
            }
            self.captured_packets.append(packet_info)
            print(f"📦 #{i+1}: {packet_info['summary']} ({packet_info['length']} bytes)")
        
        print("✅ Capture simulation completed!")
    
    def show_protocol_stats(self):
        """Show protocol statistics - FIXED VERSION"""
        if not self.captured_packets:
            print("No packets to analyze")
            return
        
        protocols = {}
        real_packets = 0
        
        for packet in self.captured_packets:
            proto = packet.get('protocol', 'Unknown')  # FIX: Use get() to avoid KeyError
            protocols[proto] = protocols.get(proto, 0) + 1
            if packet.get('real_packet', False):
                real_packets += 1
        
        print(f"\n📊 Capture Summary:")
        print(f"  Total packets: {len(self.captured_packets)}")
        print(f"  Real packets: {real_packets}")
        print(f"  Simulated packets: {len(self.captured_packets) - real_packets}")
        
        print("\n📊 Protocol Statistics:")
        for protocol, count in protocols.items():
            print(f"  {protocol}: {count} packets")