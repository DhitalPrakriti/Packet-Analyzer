# 🎨 Packet Analyzer - Frontend

React frontend for the Packet Analyzer project, providing a modern web interface for network traffic analysis.

## 🚀 Installation

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm start

# Application will open at http://localhost:3000
📦 Available Scripts
npm start - Runs the app in development mode

npm build - Builds the app for production

npm test - Launches the test runner

npm run eject - Ejects from Create React App (one-way operation)

🎯 Components
CapturePanel
Packet capture controls and settings

Real/simulation mode toggle

Capture count and duration configuration

PacketList
Display captured packets in card format

Protocol-specific styling and badges

Expandable packet analysis details

Layer-by-layer protocol information

StatisticsPanel
Traffic overview and metrics

Protocol distribution charts

Packet size analysis

Traffic rate visualization

IssuesPanel
Network issue detection display

Severity-based color coding

Security anomaly alerts

Performance problem identification

FilterPanel
Real-time packet filtering

Protocol, IP, and port-based filters

Multiple filter combination support

StoragePanel
Capture save/load functionality

File management interface

Export/import capabilities

🔌 API Integration
Services
The services/api.js file handles all backend communication:

javascript
// API endpoints
- capturePackets(count, realCapture)
- analyzePackets(packets)
- getStatistics(packets) 
- detectIssues(packets)
- saveCapture(packets, filename, format)
- loadCapture(filename)
- listCaptures()
- deleteCapture(filename)
Example Usage
javascript
import { capturePackets, analyzePackets } from './services/api';

// Capture packets
const result = await capturePackets(10, true);
if (result.success) {
  const packets = result.data.packets;
  // Process packets...
}

🛠️ Development
Dependencies
json
{
  "react": "^18.2.0",
  "react-dom": "^18.2.0",
  "axios": "^1.6.0"
}









