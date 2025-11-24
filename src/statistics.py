# src/statistics.py
import time
from collections import Counter

class TrafficStatistics:
    """
    Generates traffic statistics and analysis
    Educational tool for understanding network traffic patterns
    """
    
    def __init__(self):
        print("📊 TrafficStatistics initialized!")
    
    def generate_statistics(self, packets):
        """Generate comprehensive traffic statistics"""
        if not packets:
            print("No packets to analyze")
            return {}
        
        stats = {
            'total_packets': len(packets),
            'total_bytes': sum(p.get('length', 0) for p in packets),
            'capture_duration': self._calculate_duration(packets),
            'protocol_distribution': self._protocol_distribution(packets),
            'traffic_timeline': self._traffic_timeline(packets),
            'packet_size_distribution': self._packet_size_distribution(packets),
            'top_conversations': self._top_conversations(packets)
        }
        
        return stats
    
    def _calculate_duration(self, packets):
        """Calculate capture duration"""
        if len(packets) < 2:
            return 0
        
        timestamps = [p.get('timestamp', 0) for p in packets]
        return max(timestamps) - min(timestamps)
    
    def _protocol_distribution(self, packets):
        """Calculate protocol distribution"""
        protocols = [p.get('protocol', 'Unknown') for p in packets]
        distribution = Counter(protocols)
        
        # Add percentages
        total = len(packets)
        result = {}
        for protocol, count in distribution.items():
            percentage = (count / total) * 100
            result[protocol] = {
                'count': count,
                'percentage': round(percentage, 1)
            }
        
        return result
    
    def _traffic_timeline(self, packets):
        """Create traffic timeline (packets per second)"""
        if not packets:
            return {}
        
        timeline = {}
        for packet in packets:
            timestamp = packet.get('timestamp', 0)
            second = int(timestamp)
            timeline[second] = timeline.get(second, 0) + 1
        
        return timeline
    
    def _packet_size_distribution(self, packets):
        """Analyze packet size distribution"""
        sizes = [p.get('length', 0) for p in packets]
        
        return {
            'small': len([s for s in sizes if s < 100]),
            'medium': len([s for s in sizes if 100 <= s < 1000]),
            'large': len([s for s in sizes if s >= 1000]),
            'average_size': sum(sizes) / len(sizes) if sizes else 0,
            'min_size': min(sizes) if sizes else 0,
            'max_size': max(sizes) if sizes else 0
        }
    
    def _top_conversations(self, packets):
        """Identify top conversations (source-destination pairs)"""
        conversations = []
        
        for packet in packets:
            summary = packet.get('summary', '')
            # Extract conversation info from summary
            if '>' in summary:
                parts = summary.split('>')
                if len(parts) == 2:
                    src = parts[0].strip()
                    dst = parts[1].split('/')[0].strip() if '/' in parts[1] else parts[1].strip()
                    conversations.append(f"{src} → {dst}")
        
        return Counter(conversations).most_common(5)
    
    def display_statistics(self, stats):
        """Display statistics in educational format"""
        print("\n" + "="*60)
        print("📊 NETWORK TRAFFIC STATISTICS & ANALYSIS")
        print("="*60)
        
        print(f"\n📈 CAPTURE OVERVIEW:")
        print(f"   Total Packets: {stats['total_packets']}")
        print(f"   Total Data: {stats['total_bytes']:,} bytes")
        print(f"   Duration: {stats['capture_duration']:.2f} seconds")
        
        if stats['capture_duration'] > 0:
            packets_per_second = stats['total_packets'] / stats['capture_duration']
            print(f"   Traffic Rate: {packets_per_second:.1f} packets/second")
        
        print(f"\n🔍 PROTOCOL DISTRIBUTION:")
        for protocol, data in stats['protocol_distribution'].items():
            print(f"   {protocol}: {data['count']} packets ({data['percentage']}%)")
        
        print(f"\n📦 PACKET SIZE ANALYSIS:")
        size_data = stats['packet_size_distribution']
        print(f"   Small packets (<100B): {size_data['small']}")
        print(f"   Medium packets (100B-1KB): {size_data['medium']}")
        print(f"   Large packets (≥1KB): {size_data['large']}")
        print(f"   Average size: {size_data['average_size']:.1f} bytes")
        print(f"   Size range: {size_data['min_size']}-{size_data['max_size']} bytes")
        
        print(f"\n💬 TOP CONVERSATIONS:")
        for i, (conversation, count) in enumerate(stats['top_conversations'], 1):
            print(f"   {i}. {conversation} ({count} packets)")
        
        print(f"\n⏰ TRAFFIC TIMELINE:")
        timeline = stats['traffic_timeline']
        if timeline:
            busiest_second = max(timeline.items(), key=lambda x: x[1])
            print(f"   Busiest second: {busiest_second[1]} packets at timestamp {busiest_second[0]}")
        else:
            print("   No timeline data available")
        
        print("\n" + "="*60)