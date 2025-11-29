# 🕵️‍♂️ Packet Analyzer - Professional Network Analysis Tool

A comprehensive, educational network packet analyzer built with Python. Capture, analyze, and understand network traffic with real-time parsing and professional-grade visualization.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![React](https://img.shields.io/badge/react-18%2B-blue)

## ✨ Features

### 🔍 Core Capabilities
- **Real & Simulated Packet Capture** - Real network traffic or safe simulation
- **Protocol Parsing** - Deep analysis of Ethernet, IP, TCP, UDP, ICMP
- **Smart Filtering** - Filter by protocol, IP, port, and more
- **Traffic Statistics** - Comprehensive analytics and visualization
- **Issue Detection** - Automatic network problem detection
- **Data Persistence** - Save/load captures in JSON or Pickle format

### 🎯 Educational Focus
- **Layer-by-Layer Analysis** - Understand OSI model in practice
- **Protocol Explanations** - Learn how each protocol works
- **Security Insights** - Detect suspicious network activity
- **Real-time Learning** - See networking concepts in action

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Administrative privileges (for real packet capture)
- Node.js 16+ (for frontend)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/DhitalPrakriti/Packet-Analyzer.git
cd Packet-Analyzer

**Backend setup**
**# Install Python dependencies**
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run comprehensive demo
packetanalyzer --demo

# Capture 10 real packets
packetanalyzer --capture --count 10

# Capture and show statistics
packetanalyzer --capture --stats

# Full analysis with issue detection
packetanalyzer --capture --analyze --detect-issues

# Filter specific traffic
packetanalyzer --capture --filter-protocol TCP --filter-dst-ip 8.8.8.8

# Load and analyze saved capture
packetanalyzer --load capture_20231201_143022.json --stats --detect-issues

# Start the API server
cd backend/api
python app.py

# API will be available at: http://localhost:5000

# Start frontend development server
cd frontend
npm start

# Frontend will be available at: http://localhost:3000
