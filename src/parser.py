# src/parser.py
class ProtocolParser:
    """
    Parses network protocol headers for educational purposes.
    Shows exactly what happens at each layer of the network stack.
    """
    
    def __init__(self):
        print("🔍 ProtocolParser initialized!")
    
    def parse_packet(self, packet_info):
        """
        Parse a packet and return educational information about each layer
        """
        if packet_info.get('real_packet', False):
            return self._parse_real_packet(packet_info)
        else:
            return self._parse_simulated_packet(packet_info)
    
    def _parse_real_packet(self, packet_info):
        """Parse real Scapy packet with better error handling"""
        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import Ether
            
            # Get the actual packet object
            raw_packet = packet_info.get('raw_packet')
            if not raw_packet:
                return self._create_basic_analysis(packet_info, "No raw packet data available")
            
            layers = {}
            
            # Ethernet Layer (Layer 2)
            if Ether in raw_packet:
                eth = raw_packet[Ether]
                layers['ethernet'] = {
                    'source_mac': eth.src,
                    'destination_mac': eth.dst,
                    'type': eth.type,
                    'description': 'Data Link Layer - Local network delivery between devices',
                    'educational_note': 'MAC addresses identify devices on the same local network'
                }
            
            # IPv4 Layer (Layer 3)  
            if IP in raw_packet:
                ip = raw_packet[IP]
                layers['ip'] = {
                    'version': 4,
                    'source_ip': ip.src,
                    'destination_ip': ip.dst,
                    'time_to_live': ip.ttl,
                    'protocol': ip.proto,
                    'length': ip.len,
                    'description': 'Network Layer - Routes packets between different networks using IPv4',
                    'educational_note': f'TTL: {ip.ttl} (prevents infinite routing loops)'
                }
            
            # IPv6 Layer (Layer 3)
            elif IPv6 in raw_packet:
                ipv6 = raw_packet[IPv6]
                layers['ipv6'] = {
                    'version': 6,
                    'source_ip': ipv6.src,
                    'destination_ip': ipv6.dst,
                    'hop_limit': ipv6.hlim,
                    'length': ipv6.plen,
                    'description': 'Network Layer - Next-generation Internet Protocol with larger address space',
                    'educational_note': 'IPv6 uses 128-bit addresses vs IPv4 32-bit addresses'
                }
            
            # TCP Layer (Layer 4)
            if TCP in raw_packet:
                tcp = raw_packet[TCP]
                layers['tcp'] = {
                    'source_port': tcp.sport,
                    'destination_port': tcp.dport,
                    'sequence_number': tcp.seq,
                    'acknowledgment_number': tcp.ack,
                    'flags': self._parse_tcp_flags(tcp.flags),
                    'window_size': tcp.window,
                    'description': 'Transport Layer - Reliable, connection-oriented communication',
                    'educational_note': 'Sequence numbers ensure data arrives in correct order'
                }
            
            # UDP Layer (Layer 4)
            if UDP in raw_packet:
                udp = raw_packet[UDP]
                layers['udp'] = {
                    'source_port': udp.sport,
                    'destination_port': udp.dport,
                    'length': udp.len,
                    'description': 'Transport Layer - Fast, connectionless communication',
                    'educational_note': 'Used for DNS, VoIP, and other time-sensitive applications'
                }
            
            # Special protocols
            if scapy.ICMPv6ND_RA in raw_packet:
                layers['icmpv6'] = {
                    'type': 'Router Advertisement',
                    'description': 'ICMPv6 - Router discovery and configuration',
                    'educational_note': 'Helps devices automatically configure IPv6 addresses'
                }
            elif scapy.ICMPv6MLReport2 in raw_packet:
                layers['icmpv6'] = {
                    'type': 'Multicast Listener Report',
                    'description': 'ICMPv6 - Multicast group management',
                    'educational_note': 'Devices use this to join/leave multicast groups'
                }
            
            if layers:
                return {
                    'packet_number': packet_info['number'],
                    'protocol': packet_info.get('protocol', 'Mixed'),
                    'layers': layers,
                    'summary': f"Parsed {len(layers)} protocol layers"
                }
            else:
                return self._create_basic_analysis(packet_info, "No recognizable protocol layers found")
            
        except Exception as e:
            return self._create_basic_analysis(packet_info, f"Parsing error: {str(e)}")
    
    def _create_basic_analysis(self, packet_info, message):
        """Create a basic analysis when detailed parsing fails"""
        return {
            'packet_number': packet_info['number'],
            'protocol': packet_info.get('protocol', 'Unknown'),
            'layers': {
                'basic': {
                    'summary': packet_info.get('summary', 'No summary'),
                    'length': packet_info.get('length', 0),
                    'description': 'Basic packet information',
                    'educational_note': message
                }
            },
            'summary': 'Basic analysis - ' + message
        }
    
    def _parse_tcp_flags(self, flags):
        """Convert TCP flags to human-readable format"""
        flag_descriptions = {
            'F': ('FIN', 'Connection finish'),
            'S': ('SYN', 'Synchronize sequence numbers'), 
            'R': ('RST', 'Reset connection'),
            'P': ('PSH', 'Push function'),
            'A': ('ACK', 'Acknowledgment'),
            'U': ('URG', 'Urgent pointer')
        }
        
        result = []
        for flag in str(flags):
            if flag in flag_descriptions:
                name, desc = flag_descriptions[flag]
                result.append(f"{name} - {desc}")
        
        return result if result else ['No flags set']
    
    def _parse_simulated_packet(self, packet_info):
        """Parse simulated packet with educational content"""
        return {
            'packet_number': packet_info['number'],
            'protocol': packet_info['protocol'],
            'layers': {
                'simulated': {
                    'source': packet_info['src_ip'],
                    'destination': packet_info['dst_ip'],
                    'length': packet_info['length'],
                    'description': 'Simulated packet for educational demonstration',
                    'educational_note': 'Real packets would show Ethernet, IP, and Transport layer details'
                }
            },
            'summary': 'Simulated packet analysis'
        }