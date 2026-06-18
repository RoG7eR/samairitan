import React, { useState, useEffect } from 'react';
import NetworkMap from './components/NetworkMap';

export default function App() {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState(null);
  const [loadingMap, setLoadingMap] = useState(true);
  const [sweepTarget, setSweepTarget] = useState("");
  const [isSweeping, setIsSweeping] = useState(false);
  const [consoleLog, setConsoleLog] = useState("AWAITING COMMAND INPUT...");
  const [isLocalScanning, setIsLocalScanning] = useState(false);

  // Filter States
  const [filters, setFilters] = useState({
    showInfrastructure: true,
    showDomains: true,
    criticalOnly: false
  });

  const fetchNetworkMatrix = () => {
    fetch('http://localhost:5000/api/v1/network')
      .then(res => res.json())
      .then(data => {
        setGraphData(data);
        setLoadingMap(false);
      })
      .catch(err => console.error("Database link failed:", err));
  };

  useEffect(() => {
    fetchNetworkMatrix();
  }, []);

  const handleSweepCommand = async (e) => {
    e.preventDefault();
    if (!sweepTarget.trim()) return;
    setIsSweeping(true);
    setConsoleLog(`INITIATING ACTIVE RECONNAISSANCE ON: ${sweepTarget.toUpperCase()}...`);

    try {
      const response = await fetch('http://localhost:5000/api/v1/sweep', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: sweepTarget.toLowerCase() })
      });
      const result = await response.json();
      if (response.ok) {
        setConsoleLog(`SWEEP COMPLETE. ASSIMILATED ${result.nodesAdded} NEW ASSETS.`);
        fetchNetworkMatrix(); 
        setSweepTarget("");   
      } else {
        setConsoleLog(`SWEEP FAILED: ${result.message || "TARGET UNREACHABLE"}`);
      }
    } catch (error) {
      setConsoleLog("CRITICAL FAILURE: LOST CONNECTION TO CORE SERVER.");
    } finally {
      setIsSweeping(false);
    }
  };

  const handleFilterChange = (filterName) => {
    setFilters(prev => ({ ...prev, [filterName]: !prev[filterName] }));
  };

  const handleLocalSweep = async () => {
    setIsLocalScanning(true);
    setConsoleLog("INITIALIZING PROXIMITY SWEEP ON LOCAL SUBNET...");

    try {
      const response = await fetch('http://localhost:5000/api/v1/local-sweep', {
        method: 'POST'
      });

      const result = await response.json();

      if (response.ok) {
        setConsoleLog(`PROXIMITY SCAN COMPLETE. MAPPED ${result.nodesAdded} NEIGHBORING ASSETS.`);
        fetchNetworkMatrix(); 
      } else {
        setConsoleLog(`PROXIMITY SCAN FAILED: ${result.error || "UNKNOWN ROUTER ERROR"}`);
      }
    } catch (error) {
      setConsoleLog("CRITICAL FAILURE: LOCAL GATEWAY UNREACHABLE.");
    } finally {
      setIsLocalScanning(false);
    }
  };

  return (
    <div className="bg-dark text-light min-vh-100 p-4" style={{ backgroundColor: "#0b0c10" }}>
      <header className="border-bottom border-secondary pb-3 mb-4">
        <h1 className="text-uppercase text-info" style={{ letterSpacing: "2px" }}>Samaritan Asset Index</h1>

        {/* Unified Command Line Form */}
        <form onSubmit={handleSweepCommand} className="mt-4 mb-3">
          <div className="input-group shadow">
            <span className="input-group-text bg-secondary text-info border-secondary font-monospace">ADMIN@SYSTEM:~$</span>
            <input
              type="text"
              className="form-control bg-dark text-light border-secondary font-monospace"
              placeholder="ENTER DOMAIN TARGET"
              value={sweepTarget}
              onChange={(e) => setSweepTarget(e.target.value)}
              disabled={isSweeping || isLocalScanning} 
            />
            <button 
              className={`btn ${isSweeping ? 'btn-danger' : 'btn-outline-info'} font-monospace`} 
              type="submit" 
              disabled={isSweeping || isLocalScanning}
            >
              {isSweeping ? 'EXECUTING...' : 'INITIATE SWEEP'}
            </button>
            <button
              className={`btn ${isLocalScanning ? 'btn-danger' : 'btn-outline-warning'} font-monospace`}
              type="button"
              onClick={handleLocalSweep}
              disabled={isSweeping || isLocalScanning}
            >
              {isLocalScanning ? 'SCANNING LAN...' : 'PROXIMITY SCAN'}
            </button>
          </div>

          {/* Console Log Feedback Status Line */}
          <div className="text-muted font-monospace small mt-2">
            {(isSweeping || isLocalScanning) && (
              <span className="spinner-grow spinner-grow-sm text-danger me-2" role="status"></span>
            )}
            <span className={isSweeping || isLocalScanning ? 'text-warning' : 'text-success'}>
              {consoleLog}
            </span>
          </div>
        </form>

        {/* Over-Watch Filter HUD */}
        <div className="d-flex gap-4 p-3 bg-secondary rounded border border-light shadow-sm">
          <div className="form-check form-switch">
            <input className="form-check-input" type="checkbox" role="switch" id="filterInfra"
              checked={filters.showInfrastructure} onChange={() => handleFilterChange('showInfrastructure')} />
            <label className="form-check-label font-monospace small" htmlFor="filterInfra">INFRASTRUCTURE (IPs)</label>
          </div>
          <div className="form-check form-switch">
            <input className="form-check-input" type="checkbox" role="switch" id="filterDomain"
              checked={filters.showDomains} onChange={() => handleFilterChange('showDomains')} />
            <label className="form-check-label font-monospace small" htmlFor="filterDomain">DOMAINS</label>
          </div>
          <div className="form-check form-switch">
            <input className="form-check-input" type="checkbox" role="switch" id="filterCritical"
              checked={filters.criticalOnly} onChange={() => handleFilterChange('criticalOnly')} />
            <label className="form-check-label font-monospace small text-danger" htmlFor="filterCritical">ELEVATED THREATS ONLY</label>
          </div>
        </div>
      </header>

      {/* Main Dashboard Layout Grid */}
      {loadingMap ? (
        <div className="text-center my-5 py-5">
          <div className="spinner-border text-info" role="status"></div>
        </div>
      ) : (
        <div className="row g-4">
          <div className="col-12 col-lg-8">
            <NetworkMap graphData={graphData} onSelectNode={setSelectedNode} filters={filters} />
          </div>

          <div className="col-12 col-lg-4">
            <div className="card bg-secondary text-light border-light shadow h-100">
              <div className="card-header bg-dark border-secondary">
                <h5 className="card-title mb-0 text-uppercase text-warning">Asset Profile</h5>
              </div>
              <div className="card-body">
                {selectedNode ? (
                  <div>
                    <h3 className="text-info mb-2 text-break">{selectedNode.name}</h3>
                    <p className="mb-1"><strong>Classification:</strong> {selectedNode.type}</p>
                    <p className="mb-3">
                      <strong>Threat Priority: </strong> 
                      <span className={selectedNode.threatLevel === 'Elevated' ? 'text-danger' : 'text-success'}>
                        {selectedNode.threatLevel}
                      </span>
                    </p>
                    <div className="bg-dark p-3 rounded border border-secondary font-monospace small">
                      ID: {selectedNode.id}<br/>
                      STATUS: ACTIVE<br/>
                      INTELLIGENCE LINK SECURE
                    </div>
                  </div>
                ) : (
                  <p className="text-muted fst-italic py-4 text-center font-monospace">STANDBY. AWAITING ASSET SELECTION.</p>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}