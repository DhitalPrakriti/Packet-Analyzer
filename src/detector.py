# src/detector.py
from collections import defaultdict, Counter
import time

class IssueDetector:
    """
    Detects potential network issues and anomalies
    Educational tool for understanding network troubleshooting
    """
    
    def __init__(self):
        self.detected_issues = []
        print("🚨 IssueDetector initialized!")
    
    def analyze_packets(self, packets):
        """Analyze packets for potential network issues"""
        if not packets:
            print("No packets to analyze for issues")
            return []
        
        self.detected_issues = []
        
        # Run all detection methods
        self._detect_high_retransmissions(packets)
        self._detect_unusual_traffic_patterns(packets)
        self._detect_suspicious_ports(packets)
        self._detect_broadcast_storms(packets)
        self._detect_malformed_packets(packets)
        self._detect_dns_issues(packets)
        
        return self.detected_issues
    
    def _detect_high_retransmissions(self, packets):
        """Detect potential TCP retransmission issues"""
        tcp_packets = [p for p in packets if p.get('protocol') == 'TCP']
        
        if len(tcp_packets) < 3:
            return
        
        # Look for patterns that might indicate retransmissions
        conversations = defaultdict(list)
        for packet in tcp_packets:
            summary = packet.get('summary', '')
            if '>' in summary:
                # Extract conversation key
                parts = summary.split('>')
                if len(parts) == 2:
                    conv_key = parts[0].strip() + ">" + parts[1].split('/')[0].strip()
                    conversations[conv_key].append(packet)
        
        # Check for repeated sequences that might indicate retransmissions
        for conv, conv_packets in conversations.items():
            if len(conv_packets) > 5:
                self.detected_issues.append({
                    'type': 'POTENTIAL_RETRANSMISSION',
                    'severity': 'MEDIUM',
                    'description': f'High TCP activity in conversation: {conv}',
                    'details': f'Found {len(conv_packets)} TCP packets in this conversation',
                    'educational_note': 'High TCP packet counts might indicate retransmissions due to network congestion or packet loss'
                })
    
    def _detect_unusual_traffic_patterns(self, packets):
        """Detect unusual traffic patterns"""
        if len(packets) > 20:
            # Check packet rate
            duration = max(p.get('timestamp', 0) for p in packets) - min(p.get('timestamp', 0) for p in packets)
            if duration > 0:
                packet_rate = len(packets) / duration
                if packet_rate > 50:  # More than 50 packets per second
                    self.detected_issues.append({
                        'type': 'HIGH_TRAFFIC_RATE',
                        'severity': 'LOW',
                        'description': 'Unusually high packet rate detected',
                        'details': f'Packet rate: {packet_rate:.1f} packets/second',
                        'educational_note': 'High packet rates might indicate network scanning, DDoS attempts, or legitimate heavy traffic'
                    })
    
    def _detect_suspicious_ports(self, packets):
        """Detect traffic on suspicious or unusual ports"""
        suspicious_ports = {
            23: 'Telnet (unencrypted, often targeted)',
            135: 'Windows RPC (common attack vector)',
            139: 'NetBIOS (often scanned)',
            445: 'SMB (common in ransomware attacks)',
            1433: 'SQL Server (common target)',
            3389: 'RDP (common brute force target)'
        }
        
        for packet in packets:
            summary = packet.get('summary', '').lower()
            for port, description in suspicious_ports.items():
                if f':{port}' in summary or f'>{port}' in summary:
                    self.detected_issues.append({
                        'type': 'SUSPICIOUS_PORT',
                        'severity': 'MEDIUM',
                        'description': f'Traffic on potentially suspicious port {port}',
                        'details': f'{description} - Packet: {summary[:100]}...',
                        'educational_note': 'Monitor traffic on these ports for potential security issues'
                    })
                    break
    
    def _detect_broadcast_storms(self, packets):
        """Detect potential broadcast/multicast storms"""
        broadcast_packets = []
        multicast_packets = []
        
        for packet in packets:
            summary = packet.get('summary', '')
            # Check for broadcast/multicast addresses
            if 'ff02::' in summary or '224.0.0.' in summary or '255.255.255.255' in summary:
                if 'ff02::' in summary:
                    multicast_packets.append(packet)
                else:
                    broadcast_packets.append(packet)
        
        if len(broadcast_packets) > len(packets) * 0.3:  # More than 30% broadcast
            self.detected_issues.append({
                'type': 'POTENTIAL_BROADCAST_STORM',
                'severity': 'HIGH',
                'description': 'High volume of broadcast traffic detected',
                'details': f'{len(broadcast_packets)} broadcast packets ({len(broadcast_packets)/len(packets)*100:.1f}% of total)',
                'educational_note': 'Broadcast storms can degrade network performance and may indicate misconfigured devices'
            })
        
        if len(multicast_packets) > len(packets) * 0.5:  # More than 50% multicast
            self.detected_issues.append({
                'type': 'HIGH_MULTICAST_TRAFFIC',
                'severity': 'MEDIUM',
                'description': 'High volume of multicast traffic detected',
                'details': f'{len(multicast_packets)} multicast packets ({len(multicast_packets)/len(packets)*100:.1f}% of total)',
                'educational_note': 'Excessive multicast traffic might indicate issues with multicast applications or network configuration'
            })
    
    def _detect_malformed_packets(self, packets):
        """Detect potentially malformed or unusual packets"""
        for packet in packets:
            length = packet.get('length', 0)
            summary = packet.get('summary', '')
            
            # Check for unusually small packets (might be malformed)
            if length < 60 and 'TCP' in summary:
                self.detected_issues.append({
                    'type': 'UNUSUALLY_SMALL_PACKET',
                    'severity': 'LOW',
                    'description': 'Very small TCP packet detected',
                    'details': f'Packet size: {length} bytes - {summary[:80]}...',
                    'educational_note': 'Very small TCP packets might be keep-alives, but could also indicate malformed traffic'
                })
    
    def _detect_dns_issues(self, packets):
        """Detect potential DNS-related issues"""
        dns_packets = [p for p in packets if 'DNS' in p.get('summary', '')]
        
        if len(dns_packets) > 5:
            # Check for repeated DNS queries (might indicate issues)
            dns_queries = []
            for packet in dns_packets:
                summary = packet.get('summary', '')
                if 'Qry' in summary:
                    dns_queries.append(summary)
            
            if len(dns_queries) > 3:
                query_counts = Counter(dns_queries)
                for query, count in query_counts.items():
                    if count > 2:  # Same query repeated multiple times
                        self.detected_issues.append({
                            'type': 'REPEATED_DNS_QUERIES',
                            'severity': 'LOW',
                            'description': 'Repeated DNS queries detected',
                            'details': f'Query repeated {count} times: {query[:100]}...',
                            'educational_note': 'Repeated DNS queries might indicate DNS resolution issues or misconfigured applications'
                        })
    
    def display_issues(self):
        """Display detected issues in educational format"""
        if not self.detected_issues:
            print("✅ No network issues detected!")
            return
        
        print("\n" + "="*70)
        print("🚨 NETWORK ISSUE DETECTION REPORT")
        print("="*70)
        
        # Group by severity
        issues_by_severity = {
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for issue in self.detected_issues:
            issues_by_severity[issue['severity']].append(issue)
        
        # Display issues by severity
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            issues = issues_by_severity[severity]
            if issues:
                print(f"\n🔴 {severity} SEVERITY ISSUES:")
                for i, issue in enumerate(issues, 1):
                    print(f"   {i}. {issue['type']}")
                    print(f"      📝 {issue['description']}")
                    print(f"      🔍 {issue['details']}")
                    print(f"      💡 {issue['educational_note']}")
                    print()
        
        print("="*70)