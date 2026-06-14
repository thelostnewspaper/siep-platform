import React, { useState, useEffect, useRef } from 'react';

// API Configuration
const BASE_URL = 'http://localhost:8000';
const WS_URL = 'ws://localhost:8000/ws/telemetry';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard'); // dashboard, mesh, IDS, certificates, nis2
  const [devices, setDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  const [meshStatus, setMeshStatus] = useState({ gateways: [], blocklist: [], quarantine: [], threat_count: 0 });
  const [nis2Items, setNis2Items] = useState([]);
  const [policies, setPolicies] = useState({});
  const [wsConnected, setWsConnected] = useState(false);
  
  // UI states
  const [selectedDeviceForAttack, setSelectedDeviceForAttack] = useState('');
  const [selectedAttackType, setSelectedAttackType] = useState('ddos');
  const [agentThinking, setAgentThinking] = useState(null); // stores { device_id, action, thinking: [] }
  const [lastTelemetry, setLastTelemetry] = useState(null);
  
  // Registration Form state
  const [newDevice, setNewDevice] = useState({
    device_id: '',
    device_type: 'Temperature Sensor',
    firmware_version: 'v2.0.1',
    ip_address: '',
    gateway_node: 'Gateway Alpha'
  });
  const [provisionedCertData, setProvisionedCertData] = useState(null); // stores { cert_pem, key_pem }
  const [isRegisterModalOpen, setIsRegisterModalOpen] = useState(false);
  const [isPolicyModalOpen, setIsPolicyModalOpen] = useState(false);
  const [rootCaPem, setRootCaPem] = useState('');
  
  // NIS2 Audit editing state
  const [editingNis2Item, setEditingNis2Item] = useState(null);

  const terminalEndRef = useRef(null);

  // Connect to WebSocket on mount
  useEffect(() => {
    let ws;
    let reconnectInterval;

    function connect() {
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        setWsConnected(true);
        clearInterval(reconnectInterval);
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        if (data.type === 'state_sync') {
          setDevices(data.devices || []);
          setLogs(data.logs || []);
          setMeshStatus(data.mesh || { gateways: [], blocklist: [], quarantine: [], threat_count: 0 });
          setNis2Items(data.nis2 || []);
        } else if (data.type === 'telemetry_event') {
          setLastTelemetry(data);
          if (data.violations && data.violations.length > 0) {
            setAgentThinking({
              device_id: data.device_id,
              action: data.action,
              thinking: data.thinking,
              violations: data.violations,
              timestamp: new Date().toLocaleTimeString()
            });
          }
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        // Retry connection
        reconnectInterval = setTimeout(connect, 3000);
      };

      ws.onerror = (err) => {
        console.error('WebSocket Error:', err);
        ws.close();
      };
    }

    connect();

    // Fetch Root CA PEM
    fetch(`${BASE_URL}/api/ca/root`)
      .then(res => res.json())
      .then(data => setRootCaPem(data.root_ca_pem))
      .catch(err => console.error("Error fetching Root CA cert:", err));

    // Fetch Policies
    fetch(`${BASE_URL}/api/policies`)
      .then(res => res.json())
      .then(data => setPolicies(data))
      .catch(err => console.error("Error fetching policies:", err));

    return () => {
      if (ws) ws.close();
      clearInterval(reconnectInterval);
    };
  }, []);

  // Auto scroll terminal to bottom
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Actions
  const handleRegisterDevice = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${BASE_URL}/api/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newDevice)
      });
      if (!res.ok) {
        const err = await res.json();
        alert(err.detail || 'Failed to register device');
        return;
      }
      const data = await res.json();
      setProvisionedCertData(data);
      // Reset form
      setNewDevice({
        device_id: '',
        device_type: 'Temperature Sensor',
        firmware_version: 'v2.0.1',
        ip_address: '',
        gateway_node: 'Gateway Alpha'
      });
    } catch (err) {
      console.error(err);
      alert('Error registering device');
    }
  };

  const triggerAttack = async () => {
    if (!selectedDeviceForAttack) {
      alert('Please select a target device first');
      return;
    }
    try {
      await fetch(`${BASE_URL}/api/attack`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attack_type: selectedAttackType,
          target_device: selectedDeviceForAttack
        })
      });
      alert(`Simulation Injected: ${selectedAttackType} targeting ${selectedDeviceForAttack}`);
    } catch (err) {
      console.error(err);
      alert('Failed to inject attack simulation');
    }
  };

  const handleManualOverride = async (deviceId, action) => {
    try {
      const res = await fetch(`${BASE_URL}/api/override`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device_id: deviceId, action })
      });
      if (res.ok) {
        alert(`Device override successful: status set to ${action}`);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const handleUpdatePolicy = async (key, val) => {
    try {
      await fetch(`${BASE_URL}/api/policies/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value: String(val) })
      });
      setPolicies(prev => ({ ...prev, [key]: val }));
    } catch (err) {
      console.error(err);
    }
  };

  const handleUpdateNis2 = async (e) => {
    e.preventDefault();
    try {
      const res = await fetch(`${BASE_URL}/api/nis2/update`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: editingNis2Item.id,
          status: editingNis2Item.status,
          notes: editingNis2Item.notes
        })
      });
      if (res.ok) {
        setNis2Items(prev => prev.map(item => item.id === editingNis2Item.id ? editingNis2Item : item));
        setEditingNis2Item(null);
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Helper selectors
  const totalCount = devices.length;
  const onlineCount = devices.filter(d => d.status === 'online').length;
  const restrictedCount = devices.filter(d => d.status === 'restricted').length;
  const blockedCount = devices.filter(d => d.status === 'blocked').length;

  // Render subcomponents
  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="logo-section">
          <div className="logo-icon">S</div>
          <div className="logo-text">
            <h1>SIEP Platform</h1>
            <span>Secure Edge Gateway</span>
          </div>
        </div>

        <nav>
          <ul className="nav-list">
            <li className="nav-item">
              <button 
                className={`nav-link ${activeTab === 'dashboard' ? 'active' : ''}`}
                onClick={() => setActiveTab('dashboard')}
              >
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <rect x="3" y="3" width="7" height="9" rx="1" />
                  <rect x="14" y="3" width="7" height="5" rx="1" />
                  <rect x="14" y="12" width="7" height="9" rx="1" />
                  <rect x="3" y="16" width="7" height="5" rx="1" />
                </svg>
                Asset Directory
              </button>
            </li>
            <li className="nav-item">
              <button 
                className={`nav-link ${activeTab === 'mesh' ? 'active' : ''}`}
                onClick={() => setActiveTab('mesh')}
              >
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                </svg>
                Security Mesh
              </button>
            </li>
            <li className="nav-item">
              <button 
                className={`nav-link ${activeTab === 'IDS' ? 'active' : ''}`}
                onClick={() => setActiveTab('IDS')}
              >
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                IDS & Agent
              </button>
            </li>
            <li className="nav-item">
              <button 
                className={`nav-link ${activeTab === 'certificates' ? 'active' : ''}`}
                onClick={() => setActiveTab('certificates')}
              >
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z" />
                  <path d="M8 12h8M12 8v8" />
                </svg>
                PKI Management
              </button>
            </li>
            <li className="nav-item">
              <button 
                className={`nav-link ${activeTab === 'nis2' ? 'active' : ''}`}
                onClick={() => setActiveTab('nis2')}
              >
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                  <path d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-2.583 1.94 1.94 0 013.438 0 3.42 3.42 0 001.946 2.583c.963.307 1.8.878 2.451 1.63a1.94 1.94 0 011.896 2.87c.189.988.102 2.015-.258 2.946a1.94 1.94 0 01-1.01 3.328 3.42 3.42 0 00-2.316 2.24 1.94 1.94 0 01-3.69 0 3.42 3.42 0 00-2.317-2.24 1.94 1.94 0 01-1.01-3.328c-.36-.931-.447-1.958-.258-2.946a1.94 1.94 0 011.896-2.87c.652-.752 1.488-1.323 2.451-1.63z" />
                </svg>
                NIS2 Compliance
              </button>
            </li>
          </ul>
        </nav>
        
        <div className="sidebar-footer">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', marginBottom: '4px' }}>
            <span className={`status-indicator ${wsConnected ? 'bg-success pulse-indicator' : 'bg-danger'}`} 
                  style={{ backgroundColor: wsConnected ? 'var(--success)' : 'var(--danger)' }}></span>
            <span>{wsConnected ? 'Mesh Connected' : 'Mesh Offline'}</span>
          </div>
          <span>SIEP Gateway v1.2</span>
        </div>
      </aside>

      {/* Main Content Pane */}
      <main className="main-content">
        
        {/* Page Title & Status Header */}
        <header className="page-header">
          <div className="header-title">
            {activeTab === 'dashboard' && (
              <>
                <h2>Operational Asset Inventory</h2>
                <p>NIS2 asset lifecycle tracking and real-time security postures.</p>
              </>
            )}
            {activeTab === 'mesh' && (
              <>
                <h2>Distributed Security Mesh</h2>
                <p>Distributed gateway telemetry replication and synced device blocklists.</p>
              </>
            )}
            {activeTab === 'IDS' && (
              <>
                <h2>Intrusion Detection System</h2>
                <p>Real-time network inspect analyzer and autonomous response flow agent.</p>
              </>
            )}
            {activeTab === 'certificates' && (
              <>
                <h2>PKI & Certificate Authority</h2>
                <p>Generate, issue, and manage cryptographic identities for industrial nodes.</p>
              </>
            )}
            {activeTab === 'nis2' && (
              <>
                <h2>NIS2 Compliance Registry</h2>
                <p>Self-assessment audit scores matching Danish Cybersecurity and Critical Infrastructure rules.</p>
              </>
            )}
          </div>
          
          <div className="header-actions">
            <button className="btn btn-secondary" onClick={() => setIsPolicyModalOpen(true)}>
              <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" style={{ marginRight: '4px' }}>
                <path d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              Policy Rules
            </button>
            <button className="btn btn-primary" onClick={() => setIsRegisterModalOpen(true)}>
              <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" style={{ marginRight: '4px' }}>
                <path d="M12 4v16m8-8H4" />
              </svg>
              Register Node
            </button>
          </div>
        </header>

        {/* Global Summary Statistics */}
        <section className="summary-grid">
          <div className="summary-card">
            <div className="summary-card-header">
              <span>Total Managed Assets</span>
              <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
            </div>
            <div className="summary-card-value">{totalCount}</div>
            <div className="summary-card-footer">Registered certificates</div>
          </div>
          <div className="summary-card">
            <div className="summary-card-header">
              <span>Trusted Devices</span>
              <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" className="text-success"><path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            </div>
            <div className="summary-card-value text-success">{onlineCount}</div>
            <div className="summary-card-footer">Normal verification</div>
          </div>
          <div className="summary-card">
            <div className="summary-card-header">
              <span>Quarantined</span>
              <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" className="text-warning"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
            </div>
            <div className="summary-card-value text-warning">{restrictedCount}</div>
            <div className="summary-card-footer">Adaptive containment</div>
          </div>
          <div className="summary-card">
            <div className="summary-card-header">
              <span>Blocked Endpoints</span>
              <svg width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24" className="text-danger"><path d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
            </div>
            <div className="summary-card-value text-danger">{blockedCount}</div>
            <div className="summary-card-footer">Mesh firewall drops</div>
          </div>
        </section>

        {/* Dynamic Tab Panes */}
        
        {/* TABS 1: ASSET DIRECTORY */}
        {activeTab === 'dashboard' && (
          <div className="dashboard-grid-2x1">
            
            {/* Devices panel */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Connected Industrial Hardware</h3>
                  <p>Real-time physical values and dynamic trust scoring.</p>
                </div>
              </div>
              <div className="table-wrapper">
                <table className="siep-table">
                  <thead>
                    <tr>
                      <th>Device ID</th>
                      <th>Type</th>
                      <th>Gateway Node</th>
                      <th>IP Address</th>
                      <th>Firmware</th>
                      <th>Trust Score</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map(d => (
                      <tr key={d.device_id}>
                        <td><strong>{d.device_id}</strong></td>
                        <td>{d.device_type}</td>
                        <td>{d.gateway_node}</td>
                        <td><code>{d.ip_address}</code></td>
                        <td>{d.firmware_version}</td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ fontWeight: 600, minWidth: '28px' }}>{d.trust_score}%</span>
                            <div className="trust-bar-container">
                              <div 
                                className="trust-bar-fill" 
                                style={{ 
                                  width: `${d.trust_score}%`, 
                                  backgroundColor: d.trust_score > 80 ? 'var(--success)' : d.trust_score > 50 ? 'var(--warning)' : 'var(--danger)' 
                                }}
                              />
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={`badge ${d.status === 'online' ? 'badge-success' : d.status === 'restricted' ? 'badge-warning' : 'badge-danger'}`}>
                            {d.status}
                          </span>
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '6px' }}>
                            {d.status === 'blocked' ? (
                              <button className="btn btn-secondary btn-sm" onClick={() => handleManualOverride(d.device_id, 'RESTORE')}>Re-authorize</button>
                            ) : (
                              <>
                                <button className="btn btn-danger btn-sm" onClick={() => handleManualOverride(d.device_id, 'BLOCK')}>Block</button>
                                {d.status === 'online' && (
                                  <button className="btn btn-secondary btn-sm" style={{ color: 'var(--warning)' }} onClick={() => handleManualOverride(d.device_id, 'QUARANTINE')}>Isolate</button>
                                )}
                                {d.status === 'restricted' && (
                                  <button className="btn btn-secondary btn-sm" onClick={() => handleManualOverride(d.device_id, 'RESTORE')}>Restore</button>
                                )}
                              </>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                    {devices.length === 0 && (
                      <tr>
                        <td colSpan="8" style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No devices found. Register a device to start.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Attack simulation control */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Threat Simulation Panel</h3>
                  <p>Inject operational attack vectors to validate the Zero Trust automated response.</p>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div className="form-group">
                  <label className="form-label">Select Target Device</label>
                  <select 
                    className="form-control"
                    value={selectedDeviceForAttack}
                    onChange={(e) => setSelectedDeviceForAttack(e.target.value)}
                  >
                    <option value="">-- Choose Device --</option>
                    {devices.map(d => (
                      <option key={d.device_id} value={d.device_id}>{d.device_id} ({d.device_type})</option>
                    ))}
                    <option value="sensor_unknown_99">Rogue Node (sensor_unknown_99)</option>
                  </select>
                </div>

                <div className="form-group">
                  <label className="form-label">Select Threat Vector</label>
                  <select 
                    className="form-control"
                    value={selectedAttackType}
                    onChange={(e) => setSelectedAttackType(e.target.value)}
                  >
                    <option value="ddos">DDoS Traffic Flooding (20x traffic rate)</option>
                    <option value="invalid_cert">Certificate Hijack (Failed Cryptographic Signature)</option>
                    <option value="rogue">Rogue Endpoint Connection (Unregistered cert access)</option>
                    <option value="sql_injection">Malicious Payload Injection (SQL statement triggers)</option>
                    <option value="physical_tampering">Physical Node Tampering (Plausibility violation)</option>
                  </select>
                </div>

                <button className="btn btn-primary" onClick={triggerAttack} style={{ alignSelf: 'flex-start' }}>
                  Inject Threat Vector
                </button>
                
                <button 
                  className="btn btn-secondary" 
                  onClick={async () => {
                    await fetch(`${BASE_URL}/api/clear_attack`, { method: 'POST' });
                    alert('Simulation state reset to normal.');
                  }}
                  style={{ alignSelf: 'flex-start', marginTop: '-8px' }}
                >
                  Reset Telemetry to Normal
                </button>

                <div style={{ padding: '12px', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)', backgroundColor: 'var(--bg-primary)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <strong>NIS2 Target:</strong> This checks continuous verification. Running an attack drops device trust score, triggers an alert, synchronizes the block across all gateways, and updates the incident response logs automatically.
                </div>
              </div>
            </div>

          </div>
        )}

        {/* TABS 2: DISTRIBUTED SECURITY MESH */}
        {activeTab === 'mesh' && (
          <div className="dashboard-grid-1x1">
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Industrial Mesh Topology</h3>
                  <p>Distributed security nodes replicating blacklists in real-time.</p>
                </div>
              </div>
              
              {/* Mesh visual canvas */}
              <div className="mesh-topology">
                {/* Gateway 1: Alpha */}
                <div className="mesh-node mesh-node-gw" style={{ left: '20%', top: '25%' }}>
                  <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" /></svg>
                  <span className="mesh-node-title">Gateway Alpha</span>
                </div>
                {/* Gateway 2: Beta */}
                <div className="mesh-node mesh-node-gw" style={{ right: '20%', top: '25%' }}>
                  <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" /></svg>
                  <span className="mesh-node-title">Gateway Beta</span>
                </div>
                {/* Gateway 3: Gamma */}
                <div className="mesh-node mesh-node-gw" style={{ left: '50%', transform: 'translateX(-50%)', bottom: '15%' }}>
                  <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" /></svg>
                  <span className="mesh-node-title">Gateway Gamma</span>
                </div>

                {/* Lines between gateways */}
                <svg className="mesh-line-container">
                  {/* Alpha to Beta */}
                  <line x1="26%" y1="35%" x2="74%" y2="35%" stroke="var(--primary)" strokeWidth="2" strokeDasharray="5,5" />
                  {/* Alpha to Gamma */}
                  <line x1="26%" y1="35%" x2="50%" y2="73%" stroke="var(--primary)" strokeWidth="2" strokeDasharray="5,5" />
                  {/* Beta to Gamma */}
                  <line x1="74%" y1="35%" x2="50%" y2="73%" stroke="var(--primary)" strokeWidth="2" strokeDasharray="5,5" />
                </svg>

                {/* Dynamic device indicators floating */}
                {devices.map((d, index) => {
                  let left = '10%';
                  let top = '10%';
                  
                  if (d.gateway_node === 'Gateway Alpha') {
                    left = index === 0 ? '15%' : '25%';
                    top = index === 0 ? '55%' : '10%';
                  } else if (d.gateway_node === 'Gateway Beta') {
                    left = index === 1 ? '75%' : '85%';
                    top = index === 1 ? '55%' : '10%';
                  } else {
                    left = index === 2 ? '38%' : '58%';
                    top = index === 2 ? '82%' : '82%';
                  }
                  
                  return (
                    <div 
                      key={d.device_id} 
                      className="mesh-node mesh-node-sensor"
                      style={{ 
                        left, 
                        top,
                        borderColor: d.status === 'online' ? 'var(--success)' : d.status === 'restricted' ? 'var(--warning)' : 'var(--danger)',
                        backgroundColor: d.status === 'online' ? 'var(--success-light)' : d.status === 'restricted' ? 'var(--warning-light)' : 'var(--danger-light)'
                      }}
                    >
                      <span className="mesh-node-title" style={{ fontSize: '0.65rem' }}>{d.device_id}</span>
                      <span style={{ fontSize: '0.55rem', color: 'var(--text-muted)' }}>{d.trust_score}%</span>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Mesh Threat Replication Telemetry</h3>
                  <p>Demonstrates distributed synchronization of threat intelligence.</p>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                
                <div style={{ display: 'flex', gap: '16px' }}>
                  <div style={{ flex: 1, padding: '16px', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)' }}>
                    <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>Sync State</h4>
                    <p style={{ fontSize: '1.25rem', fontWeight: 700, margin: '8px 0 2px' }}>Fully Synced</p>
                    <span style={{ fontSize: '0.75rem', color: 'var(--success)' }}>✔ Gateways active & peering</span>
                  </div>
                  <div style={{ flex: 1, padding: '16px', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)' }}>
                    <h4 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>Shared Blacklist</h4>
                    <p style={{ fontSize: '1.25rem', fontWeight: 700, margin: '8px 0 2px' }}>{meshStatus.blocklist.length} IP Block rules</p>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Distributed Firewall Drop</span>
                  </div>
                </div>

                <div style={{ padding: '16px', backgroundColor: 'var(--bg-tertiary)', borderRadius: 'var(--radius)' }}>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '10px' }}>Active Peering Nodes</h4>
                  <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '0.85rem' }}>
                    {meshStatus.gateways.map(g => (
                      <li key={g} style={{ display: 'flex', justifyContent: 'between', alignItems: 'center' }}>
                        <span style={{ fontWeight: 500 }}>{g}</span>
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                          Local Quarantine: {meshStatus.quarantine.length} | Blacklist: {meshStatus.blocklist.length}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>

                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                  <strong>How the Mesh Works:</strong> When Gateway Alpha detects a compromised device (e.g. SQL Injection on <code>sensor_01</code>), the local incident response engine immediately drops its local connection. The mesh database broadcasts the compromised device ID. Gateway Beta and Gateway Gamma automatically add the IP to their blocklists to prevent cross-gateway spoofing.
                </div>

              </div>
            </div>
          </div>
        )}

        {/* TABS 3: IDS & AGENT PLAYGROUND */}
        {activeTab === 'IDS' && (
          <div className="dashboard-grid-2x1">
            
            {/* Real-time event log */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Real-time Network Audit & Event Feed</h3>
                  <p>Visualizing every incoming transaction validated at edge interfaces.</p>
                </div>
              </div>
              <div className="terminal-output">
                {logs.map((log) => (
                  <div key={log.id} className="terminal-line">
                    <span className="text-muted">[{new Date(log.timestamp).toLocaleTimeString()}]</span>{' '}
                    <span style={{ 
                      color: log.level === 'CRITICAL' ? 'var(--danger)' : log.level === 'MAJOR' ? 'var(--warning)' : '#38bdf8' 
                    }}>
                      [{log.level}]
                    </span>{' '}
                    <span>({log.gateway})</span>:{' '}
                    <span>{log.message}</span>
                    {log.action_taken && (
                      <span style={{ color: 'var(--success)', marginLeft: '8px' }}>
                        [{log.action_taken}]
                      </span>
                    )}
                  </div>
                ))}
                {logs.length === 0 && (
                  <div style={{ color: 'var(--text-muted)', textAlign: 'center', marginTop: '20px' }}>No events recorded. Telemetry simulation starting...</div>
                )}
                <div ref={terminalEndRef} />
              </div>
            </div>

            {/* Autonomous Response Agent */}
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Autonomous Incident Response Agent</h3>
                  <p>Reasoning trace showing the agent's Zero Trust decision playbooks.</p>
                </div>
              </div>

              {agentThinking ? (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'between', alignItems: 'center', marginBottom: '16px' }}>
                    <span style={{ fontWeight: 600 }}>Target: <code style={{ backgroundColor: 'var(--bg-tertiary)', padding: '2px 6px', borderRadius: '4px' }}>{agentThinking.device_id}</code></span>
                    <span className="badge badge-danger" style={{ marginLeft: 'auto' }}>{agentThinking.action}</span>
                  </div>
                  
                  <div className="agent-flow-container">
                    {agentThinking.thinking.map((step, idx) => (
                      <div key={idx} className="agent-step">
                        <div className="agent-step-icon">{idx + 1}</div>
                        <div className="agent-step-text">{step}</div>
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                    <button className="btn btn-secondary btn-sm" onClick={() => handleManualOverride(agentThinking.device_id, 'RESTORE')}>
                      Override & Restore Device
                    </button>
                    <button className="btn btn-secondary btn-sm" onClick={() => setAgentThinking(null)}>
                      Clear Panel
                    </button>
                  </div>
                </div>
              ) : (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px 20px', border: '1px dashed var(--border-color)', borderRadius: 'var(--radius)' }}>
                  <p><strong>Agent Inactive</strong></p>
                  <p style={{ fontSize: '0.8rem', marginTop: '6px' }}>
                    Agent dynamically runs when security violations occur. Inject a <strong>Threat Vector</strong> from the directory tab to see it make containment actions.
                  </p>
                </div>
              )}
            </div>

          </div>
        )}

        {/* TABS 4: PKI MANAGEMENT */}
        {activeTab === 'certificates' && (
          <div className="dashboard-grid-2x1">
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Certificate Authority Status</h3>
                  <p>Root CA coordinates validation of x509 cryptographic certs.</p>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label className="form-label">Root CA Subject</label>
                  <input type="text" className="form-control" readOnly value="C=DK, O=Danish Industrial Edge, CN=SIEP Root CA" />
                </div>
                <div>
                  <label className="form-label">Cryptographic CA PEM Certificate</label>
                  <textarea 
                    className="form-control" 
                    readOnly 
                    rows="8" 
                    style={{ fontFamily: 'monospace', fontSize: '0.75rem', backgroundColor: 'var(--bg-primary)' }}
                    value={rootCaPem}
                  />
                </div>
                
                <div style={{ padding: '12px', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)', fontSize: '0.8rem', backgroundColor: 'var(--bg-primary)' }}>
                  All nodes connecting to gateways must hold a client certificate signed by the Root CA above. The validation checks validity, timestamp intervals, and revoked lists.
                </div>
              </div>
            </div>

            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>Certificates Registry</h3>
                  <p>Active cryptographic keys allocated in the SIEP registry.</p>
                </div>
              </div>
              <div className="table-wrapper" style={{ maxHeight: '400px', overflowY: 'auto' }}>
                <table className="siep-table">
                  <thead>
                    <tr>
                      <th>Subject (CN)</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map(d => (
                      <tr key={d.device_id}>
                        <td><strong>{d.device_id}</strong></td>
                        <td>
                          <span style={{ fontSize: '0.8rem', color: d.status === 'blocked' ? 'var(--danger)' : 'var(--success)' }}>
                            {d.status === 'blocked' ? 'Revoked (CRL)' : 'Active'}
                          </span>
                        </td>
                        <td>
                          {d.status !== 'blocked' ? (
                            <button className="btn btn-secondary btn-sm" style={{ color: 'var(--danger)' }} onClick={() => handleManualOverride(d.device_id, 'BLOCK')}>
                              Revoke & Block
                            </button>
                          ) : (
                            <button className="btn btn-secondary btn-sm" onClick={() => handleManualOverride(d.device_id, 'RESTORE')}>
                              Re-issue
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* TABS 5: NIS2 COMPLIANCE */}
        {activeTab === 'nis2' && (
          <div className="dashboard-grid-2x1">
            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>NIS2 Audit Checklist & Controls</h3>
                  <p>Status of critical infrastructure requirements for Danish Critical Entities.</p>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                {nis2Items.map((item) => (
                  <div key={item.id} className="checklist-item">
                    <div style={{ marginTop: '2px' }}>
                      <span className={`badge ${
                        item.status === 'Compliant' ? 'badge-success' : item.status === 'In-Progress' ? 'badge-warning' : 'badge-danger'
                      }`}>
                        {item.status}
                      </span>
                    </div>
                    <div className="checklist-content">
                      <div style={{ display: 'flex', justifyContent: 'between' }}>
                        <span className="checklist-title">{item.category} ({item.id})</span>
                        <button 
                          className="btn btn-secondary btn-sm" 
                          style={{ marginLeft: 'auto', padding: '2px 8px', fontSize: '0.7rem' }}
                          onClick={() => setEditingNis2Item(item)}
                        >
                          Edit
                        </button>
                      </div>
                      <p className="checklist-desc">{item.requirement}</p>
                      {item.notes && <div className="checklist-notes">Audit Log: {item.notes}</div>}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="panel">
              <div className="panel-header">
                <div className="panel-title">
                  <h3>NIS2 Risk Assessment Engine</h3>
                  <p>Dynamic assessment mapping cyber readiness to national standards.</p>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.9rem' }}>
                    <span>Audit Score Integration</span>
                    <span style={{ fontWeight: 600 }}>
                      {Math.round((nis2Items.filter(i => i.status === 'Compliant').length / (nis2Items.length || 1)) * 100)}% Compliance
                    </span>
                  </div>
                  <div className="trust-bar-container" style={{ height: '12px' }}>
                    <div 
                      className="trust-bar-fill" 
                      style={{ 
                        width: `${(nis2Items.filter(i => i.status === 'Compliant').length / (nis2Items.length || 1)) * 100}%`,
                        backgroundColor: 'var(--primary)'
                      }}
                    />
                  </div>
                </div>

                <div style={{ padding: '16px', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)', backgroundColor: 'var(--bg-primary)' }}>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, marginBottom: '8px' }}>Security Posture Score: C2 (Intermediate)</h4>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    Your system maps to the Danish NIS2 critical infrastructure directive. Real-time logging and distributed firewalling satisfy standard controls.
                  </p>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '8px' }}>
                    <strong>Recommendations:</strong> Update outdated firmware versions running on legacy sensors (e.g. <code>sensor_02</code>) to satisfy supply chain requirements.
                  </p>
                </div>

                <div style={{ padding: '12px', border: '1px solid var(--border-color)', borderRadius: 'var(--radius)', backgroundColor: 'var(--bg-primary)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <strong>Compliance note:</strong> SIEP records every action cryptographically. Incident responses decided by the autonomous agent can be downloaded from database audit records for legal reporting to authorities.
                </div>
              </div>
            </div>
          </div>
        )}

      </main>

      {/* REGISTRATION MODAL */}
      {isRegisterModalOpen && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>Register Industrial Device</h3>
              <button className="modal-close" onClick={() => { setIsRegisterModalOpen(false); setProvisionedCertData(null); }}>
                <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
            
            {!provisionedCertData ? (
              <form onSubmit={handleRegisterDevice}>
                <div className="form-group">
                  <label className="form-label">Device ID / Serial CN</label>
                  <input 
                    type="text" 
                    className="form-control" 
                    required 
                    placeholder="e.g. sensor_04" 
                    value={newDevice.device_id}
                    onChange={(e) => setNewDevice(prev => ({ ...prev, device_id: e.target.value }))}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Hardware Device Type</label>
                  <select 
                    className="form-control"
                    value={newDevice.device_type}
                    onChange={(e) => setNewDevice(prev => ({ ...prev, device_type: e.target.value }))}
                  >
                    <option value="Temperature Sensor">Temperature Sensor</option>
                    <option value="Vibration Sensor">Vibration Sensor</option>
                    <option value="Pressure Sensor">Pressure Sensor</option>
                    <option value="Smart Energy Meter">Smart Energy Meter</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">Firmware Version</label>
                  <input 
                    type="text" 
                    className="form-control" 
                    required 
                    placeholder="e.g. v2.0.1" 
                    value={newDevice.firmware_version}
                    onChange={(e) => setNewDevice(prev => ({ ...prev, firmware_version: e.target.value }))}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Hardware IP Address</label>
                  <input 
                    type="text" 
                    className="form-control" 
                    required 
                    placeholder="e.g. 192.168.10.85" 
                    value={newDevice.ip_address}
                    onChange={(e) => setNewDevice(prev => ({ ...prev, ip_address: e.target.value }))}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Gateway Peering Node</label>
                  <select 
                    className="form-control"
                    value={newDevice.gateway_node}
                    onChange={(e) => setNewDevice(prev => ({ ...prev, gateway_node: e.target.value }))}
                  >
                    <option value="Gateway Alpha">Gateway Alpha</option>
                    <option value="Gateway Beta">Gateway Beta</option>
                    <option value="Gateway Gamma">Gateway Gamma</option>
                  </select>
                </div>

                <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                  <button type="button" className="btn btn-secondary" style={{ flex: 1 }} onClick={() => setIsRegisterModalOpen(false)}>Cancel</button>
                  <button type="submit" className="btn btn-primary" style={{ flex: 1 }}>Issue Certificate</button>
                </div>
              </form>
            ) : (
              <div>
                <div style={{ padding: '12px', backgroundColor: 'var(--success-light)', border: '1px solid var(--success-border)', borderRadius: 'var(--radius)', fontSize: '0.85rem', color: 'var(--success)', marginBottom: '16px' }}>
                  ✔ x509 2048-bit RSA client certificate cryptographically issued successfully!
                </div>
                <div className="form-group">
                  <label className="form-label">Device Client Certificate (.crt)</label>
                  <textarea 
                    className="form-control" 
                    readOnly 
                    rows="5" 
                    style={{ fontFamily: 'monospace', fontSize: '0.75rem', backgroundColor: 'var(--bg-primary)' }}
                    value={provisionedCertData.cert_pem}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Device Private Key (.key)</label>
                  <textarea 
                    className="form-control" 
                    readOnly 
                    rows="5" 
                    style={{ fontFamily: 'monospace', fontSize: '0.75rem', backgroundColor: 'var(--bg-primary)' }}
                    value={provisionedCertData.private_key_pem}
                  />
                </div>
                <button className="btn btn-primary" style={{ width: '100%', marginTop: '16px' }} onClick={() => { setIsRegisterModalOpen(false); setProvisionedCertData(null); }}>
                  Done
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* POLICY OVERRIDE CONFIG MODAL */}
      {isPolicyModalOpen && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>Gateway Security Policies</h3>
              <button className="modal-close" onClick={() => setIsPolicyModalOpen(false)}>
                <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div className="form-group">
                <label className="form-label">Quarantine Trust Score Threshold (0-100)</label>
                <input 
                  type="number" 
                  className="form-control" 
                  min="0"
                  max="100"
                  value={policies.trust_quarantine_threshold || 70}
                  onChange={(e) => handleUpdatePolicy('trust_quarantine_threshold', e.target.value)}
                />
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Trigger dynamic restriction if trust drops below this value.</span>
              </div>

              <div className="form-group">
                <label className="form-label">Block Trust Score Threshold (0-100)</label>
                <input 
                  type="number" 
                  className="form-control" 
                  min="0"
                  max="100"
                  value={policies.trust_block_threshold || 45}
                  onChange={(e) => handleUpdatePolicy('trust_block_threshold', e.target.value)}
                />
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Trigger firewall IP blocking if trust drops below this value.</span>
              </div>

              <div className="form-group">
                <label className="form-label">DDoS Traffic Threshold (msgs/min)</label>
                <input 
                  type="number" 
                  className="form-control" 
                  value={policies.ddos_threshold_per_min || 120}
                  onChange={(e) => handleUpdatePolicy('ddos_threshold_per_min', e.target.value)}
                />
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Maximum allowable rate per device. Exceeding triggers flooding alerts.</span>
              </div>

              <button className="btn btn-primary" style={{ width: '100%', marginTop: '10px' }} onClick={() => setIsPolicyModalOpen(false)}>
                Save Config
              </button>
            </div>
          </div>
        </div>
      )}

      {/* NIS2 AUDIT EDIT MODAL */}
      {editingNis2Item && (
        <div className="modal-overlay">
          <div className="modal-content">
            <div className="modal-header">
              <h3>Edit Compliance Audit Record</h3>
              <button className="modal-close" onClick={() => setEditingNis2Item(null)}>
                <svg width="24" height="24" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
            
            <form onSubmit={handleUpdateNis2}>
              <div className="form-group">
                <label className="form-label">Requirement ID</label>
                <input type="text" className="form-control" readOnly value={editingNis2Item.id} />
              </div>
              <div className="form-group">
                <label className="form-label">Category</label>
                <input type="text" className="form-control" readOnly value={editingNis2Item.category} />
              </div>
              <div className="form-group">
                <label className="form-label">Audit Control Status</label>
                <select 
                  className="form-control"
                  value={editingNis2Item.status}
                  onChange={(e) => setEditingNis2Item(prev => ({ ...prev, status: e.target.value }))}
                >
                  <option value="Compliant">Compliant</option>
                  <option value="In-Progress">In-Progress</option>
                  <option value="Non-Compliant">Non-Compliant</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Audit Notes & Proofs</label>
                <textarea 
                  className="form-control" 
                  rows="4" 
                  required
                  value={editingNis2Item.notes}
                  onChange={(e) => setEditingNis2Item(prev => ({ ...prev, notes: e.target.value }))}
                />
              </div>

              <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                <button type="button" className="btn btn-secondary" style={{ flex: 1 }} onClick={() => setEditingNis2Item(null)}>Cancel</button>
                <button type="submit" className="btn btn-primary" style={{ flex: 1 }}>Save Changes</button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
}
