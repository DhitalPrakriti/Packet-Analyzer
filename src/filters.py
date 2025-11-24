# src/filters.py
class PacketFilter:
    """
    Custom filtering system for network packets
    Educational tool for understanding packet filtering concepts
    """
    
    def __init__(self):
        self.filters = []
        print("🔍 PacketFilter initialized!")
    
    def add_protocol_filter(self, protocol):
        """Filter by protocol type (TCP, UDP, ICMP, etc.)"""
        def protocol_filter(packet_info):
            return packet_info.get('protocol') == protocol
        self.filters.append(protocol_filter)
        print(f"✅ Added protocol filter: {protocol}")
    
    def add_ip_filter(self, src_ip=None, dst_ip=None):
        """Filter by source and/or destination IP"""
        def ip_filter(packet_info):
            if packet_info.get('real_packet', False):
                # For real packets, we need to parse the IP from summary
                summary = packet_info.get('summary', '')
                if src_ip and src_ip not in summary:
                    return False
                if dst_ip and dst_ip not in summary:
                    return False
                return True
            else:
                # For simulated packets, use the stored IPs
                if src_ip and packet_info.get('src_ip') != src_ip:
                    return False
                if dst_ip and packet_info.get('dst_ip') != dst_ip:
                    return False
                return True
        self.filters.append(ip_filter)
        print(f"✅ Added IP filter - Source: {src_ip}, Destination: {dst_ip}")
    
    def add_port_filter(self, port=None, src_port=None, dst_port=None):
        """Filter by port numbers"""
        def port_filter(packet_info):
            summary = packet_info.get('summary', '').lower()
            
            # Look for port patterns in the summary
            if port:
                if f":{port} " not in summary and f">{port}" not in summary:
                    return False
            
            if src_port:
                if f":{src_port} >" not in summary:
                    return False
            
            if dst_port:
                if f">{dst_port}" not in summary:
                    return False
            
            return True
        self.filters.append(port_filter)
        print(f"✅ Added port filter - Port: {port}, Src: {src_port}, Dst: {dst_port}")
    
    def apply_filters(self, packets):
        """Apply all filters to a list of packets"""
        filtered_packets = packets
        
        for filter_func in self.filters:
            filtered_packets = [p for p in filtered_packets if filter_func(p)]
        
        print(f"📊 Filters applied: {len(packets)} → {len(filtered_packets)} packets")
        return filtered_packets
    
    def clear_filters(self):
        """Clear all filters"""
        self.filters = []
        print("🧹 All filters cleared")
    
    def show_active_filters(self):
        """Display currently active filters"""
        if not self.filters:
            print("No active filters")
            return
        
        print("🔍 Active Filters:")
        for i, filter_func in enumerate(self.filters):
            print(f"  {i+1}. {filter_func.__name__}")