# src/storage.py
import json
import pickle
import time
import os
from datetime import datetime

class PacketStorage:
    """
    Handles saving and loading packet captures
    Educational tool for understanding data persistence and capture analysis
    """
    
    def __init__(self, storage_dir="captures"):
        self.storage_dir = storage_dir
        self._ensure_storage_dir()
        print("💾 PacketStorage initialized!")
    
    def _ensure_storage_dir(self):
        """Create storage directory if it doesn't exist"""
        if not os.path.exists(self.storage_dir):
            os.makedirs(self.storage_dir)
            print(f"📁 Created storage directory: {self.storage_dir}")
    
    def save_capture(self, packets, filename=None, format='json'):
        """
        Save packet capture to file
        
        Args:
            packets: List of packet dictionaries
            filename: Custom filename (optional)
            format: 'json' or 'pkl' (pickle)
        """
        if not packets:
            print("❌ No packets to save")
            return False
        
        # Generate filename if not provided
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"capture_{timestamp}.{format}"
        else:
            # Ensure file extension matches format
            if not filename.endswith(f'.{format}'):
                filename = f"{filename}.{format}"
        
        filepath = os.path.join(self.storage_dir, filename)
        
        try:
            if format == 'json':
                self._save_json(packets, filepath)
            elif format == 'pkl':
                self._save_pickle(packets, filepath)
            else:
                print(f"❌ Unsupported format: {format}")
                return False
            
            print(f"✅ Capture saved: {filepath}")
            print(f"   📦 Packets: {len(packets)}")
            print(f"   📊 Format: {format.upper()}")
            return True
            
        except Exception as e:
            print(f"❌ Error saving capture: {e}")
            return False
    
    def _save_json(self, packets, filepath):
        """Save packets as JSON (human-readable)"""
        # Convert packets to JSON-serializable format
        serializable_packets = []
        for packet in packets:
            serializable_packet = packet.copy()
            
            # Remove non-serializable objects
            if 'raw_packet' in serializable_packet:
                del serializable_packet['raw_packet']
            
            # Convert any non-serializable objects to strings
            for key, value in serializable_packet.items():
                if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
                    serializable_packet[key] = str(value)
            
            serializable_packets.append(serializable_packet)
        
        # Add metadata
        capture_data = {
            'metadata': {
                'version': '1.0',
                'capture_date': datetime.now().isoformat(),
                'total_packets': len(packets),
                'total_bytes': sum(p.get('length', 0) for p in packets),
                'protocols': list(set(p.get('protocol', 'Unknown') for p in packets))
            },
            'packets': serializable_packets
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(capture_data, f, indent=2, ensure_ascii=False)
    
    def _save_pickle(self, packets, filepath):
        """Save packets as pickle (preserves objects, smaller file size)"""
        capture_data = {
            'metadata': {
                'version': '1.0',
                'capture_date': datetime.now().isoformat(),
                'total_packets': len(packets),
                'total_bytes': sum(p.get('length', 0) for p in packets),
                'protocols': list(set(p.get('protocol', 'Unknown') for p in packets))
            },
            'packets': packets
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(capture_data, f)
    
    def load_capture(self, filename):
        """
        Load packet capture from file
        
        Args:
            filename: Name of the capture file to load
        """
        filepath = os.path.join(self.storage_dir, filename)
        
        if not os.path.exists(filepath):
            print(f"❌ Capture file not found: {filepath}")
            return None
        
        try:
            if filename.endswith('.json'):
                return self._load_json(filepath)
            elif filename.endswith('.pkl'):
                return self._load_pickle(filepath)
            else:
                print(f"❌ Unsupported file format: {filename}")
                return None
                
        except Exception as e:
            print(f"❌ Error loading capture: {e}")
            return None
    
    def _load_json(self, filepath):
        """Load packets from JSON file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            capture_data = json.load(f)
        
        self._display_capture_info(capture_data['metadata'], filepath)
        return capture_data['packets']
    
    def _load_pickle(self, filepath):
        """Load packets from pickle file"""
        with open(filepath, 'rb') as f:
            capture_data = pickle.load(f)
        
        self._display_capture_info(capture_data['metadata'], filepath)
        return capture_data['packets']
    
    def _display_capture_info(self, metadata, filepath):
        """Display information about loaded capture"""
        print(f"✅ Capture loaded: {os.path.basename(filepath)}")
        print(f"   📅 Date: {metadata.get('capture_date', 'Unknown')}")
        print(f"   📦 Packets: {metadata.get('total_packets', 0)}")
        print(f"   📊 Data: {metadata.get('total_bytes', 0):,} bytes")
        print(f"   🔍 Protocols: {', '.join(metadata.get('protocols', []))}")
    
    def list_captures(self):
        """List all available capture files"""
        if not os.path.exists(self.storage_dir):
            print("📁 No captures directory found")
            return []
        
        capture_files = []
        for filename in os.listdir(self.storage_dir):
            if filename.endswith(('.json', '.pkl')):
                filepath = os.path.join(self.storage_dir, filename)
                file_info = {
                    'filename': filename,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath))
                }
                capture_files.append(file_info)
        
        if not capture_files:
            print("📁 No capture files found")
            return []
        
        # Sort by modification time (newest first)
        capture_files.sort(key=lambda x: x['modified'], reverse=True)
        
        print("\n📁 AVAILABLE CAPTURES:")
        print("-" * 60)
        for i, file_info in enumerate(capture_files, 1):
            size_kb = file_info['size'] / 1024
            modified_str = file_info['modified'].strftime("%Y-%m-%d %H:%M:%S")
            print(f"{i}. {file_info['filename']}")
            print(f"   📏 Size: {size_kb:.1f} KB")
            print(f"   ⏰ Modified: {modified_str}")
            print()
        
        return capture_files
    
    def delete_capture(self, filename):
        """Delete a capture file"""
        filepath = os.path.join(self.storage_dir, filename)
        
        if not os.path.exists(filepath):
            print(f"❌ Capture file not found: {filename}")
            return False
        
        try:
            os.remove(filepath)
            print(f"🗑️  Deleted capture: {filename}")
            return True
        except Exception as e:
            print(f"❌ Error deleting capture: {e}")
            return False