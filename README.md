# Samaritan Asset Index

An end-to-end, real-time tactical reconnaissance and asset mapping platform. Samaritan establishes a live graph architecture that ingests external open-source intelligence (OSINT) via Certificate Transparency logs and maps local network proximity using Address Resolution Protocol (ARP) tables, visualizing infrastructure dependencies instantly via an interactive D3.js physics-directed engine.

## 🛠️ System Architecture

The platform bridges active network reconnaissance directly into a native graph database to capture infrastructure relationships (`OWNS`, `RESOLVES_TO`, `LOCAL_ADJACENCY`).

- **Frontend:** React (Vite), D3.js (Force-directed physics simulation), Bootstrap / Custom Tactical CSS.
    
- **Backend:** Node.js, Express API, Native OS Utilities (`dns`, `child_process`).
    
- **Database:** Neo4j Graph Database (Cypher Query Language).
    

## 🚀 Deployment Guide

### Prerequisites

- [Node.js](https://nodejs.org/ "null") (v18+ recommended)
    
- [Neo4j Desktop](https://neo4j.com/download/ "null") or Neo4j AuraDB (Cloud)
    

### 1. Database Configuration

Ensure your Neo4j instance is running and set up an empty database. Take note of your connection URI, username, and password.

### 2. Backend Setup

1. Clone or navigate to your repository and enter the backend directory:
    
    ```
    cd backend
    ```
    
2. Install the core dependencies:
    
    ```
    npm install express neo4j-driver cors dotenv
    ```
    
3. Create a `.env` file in the root of the `backend/` directory:
    
    ```
    PORT=5000
    NEO4J_URI=bolt://localhost:7687
    NEO4J_USER=neo4j
    NEO4J_PASSWORD=your_secure_password
    ```
    
4. Fire up the backend engine:
    
    ```
    node server.js
    ```
    

### 3. Frontend Setup

1. Navigate to the frontend directory:
    
    ```
    cd ../frontend
    ```
    
2. Install the visualization stack:
    
    ```
    npm install d3 bootstrap
    ```
    
3. Boot the React development server:
    
    ```
    npm run dev
    ```
    
4. Open your browser and point it to `http://localhost:5173`.
    

## 🎮 Tactical Capabilities

| **Feature**              | **Execution Source**               | **Graph Impact**                                                                                |
| ------------------------ | ---------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Outbound OSINT Sweep** | `crt.sh` CT Logs + Live DNS Lookup | Maps public subdomains and points them to their active resolving IP infrastructures.            |
| **Proximity Scan**       | System ARP Cache Table (`arp -a`)  | Discovers active hardware assets sharing the immediate localized network domain.                |
| **Adjacency Focus**      | D3 Node Trigger Engine             | Isolates selected nodes and highlights 1st-degree connections while dimming background noise.   |
| **Over-Watch Filters**   | Dynamic React State Hooks          | Instantly drops or adds Asset Classifications from the visual layout without refreshing the DB. |

## 📂 Project Directory Layout

```
samaritan-asset-index/
├── backend/
│   ├── config/
│   │   └── db.js            # Neo4j connection pool setup
│   ├── routes/
│   │   └── network.js       # Core API endpoints (/network, /sweep, /local-sweep)
│   ├── services/
│   │   ├── osint.js         # External CT log gathering & DNS resolver
│   │   └── localScanner.js  # OS-level local ARP cache scanner
│   ├── server.js            # Express server initialization
│   └── .env                 # System environment secrets
└── frontend/
    ├── src/
    │   ├── components/
    │   │   └── NetworkMap.jsx # Interactive D3.js canvas & physics map
    │   ├── App.jsx          # Unified dashboard command center
    │   └── main.jsx         # React application root DOM bridge
```

## 🛡️ License and Usage Note

This software is built strictly for authorized security auditing, threat modeling, and educational target visualization. Ensure you possess explicit permission before running infrastructure-level reconnaissance sweeps against public entities.