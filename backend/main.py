import asyncio
import json
import logging
from typing import Dict, List, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import db
from ca import MiniCA
from trust_engine import TrustEngine
from mesh import DistributedMesh
from agent import AutonomousAgent
from simulator import DeviceSimulator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SIEP")

app = FastAPI(title="SIEP Backend", description="Secure Industrial Edge Platform API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize core modules
ca = MiniCA()
trust_engine = TrustEngine()
mesh = DistributedMesh()
agent = AutonomousAgent()
simulator = DeviceSimulator()

# Active WebSocket connections
active_connections: Set[WebSocket] = set()

# Models
class DeviceRegisterRequest(BaseModel):
    device_id: str
    device_type: str
    firmware_version: str
    ip_address: str
    gateway_node: str

class AttackRequest(BaseModel):
    attack_type: str  # "ddos", "rogue", "invalid_cert", "sql_injection", "physical_tampering"
    target_device: str

class OverrideRequest(BaseModel):
    device_id: str
    action: str  # "BLOCK", "QUARANTINE", "RESTORE"

class PolicyUpdateRequest(BaseModel):
    key: str
    value: str

class Nis2UpdateRequest(BaseModel):
    id: str
    status: str
    notes: str

# Helper: broadcast to WebSockets
async def broadcast_ws(data: dict):
    if not active_connections:
        return
    message = json.dumps(data)
    dead_connections = set()
    for ws in active_connections:
        try:
            await ws.send_text(message)
        except Exception:
            dead_connections.add(ws)
    for ws in dead_connections:
        active_connections.remove(ws)

# Seed DB with default devices on startup
def seed_default_devices():
    devices_in_db = db.get_devices()
    device_ids_in_db = {d["device_id"] for d in devices_in_db}
    
    for dev_id, config in simulator.devices.items():
        if dev_id not in device_ids_in_db:
            # Issue cryptographic cert for this device
            cert_pem, _ = ca.issue_device_cert(dev_id, expiry_days=365)
            db.register_device(
                device_id=dev_id,
                cert_pem=cert_pem,
                firmware=config["firmware_version"],
                ip=config["ip_address"],
                gateway=config["gateway_node"],
                device_type=config["device_type"]
            )
            db.add_audit_log(
                level="INFO",
                device_id=dev_id,
                gateway=config["gateway_node"],
                message=f"PKI Registry: Issued 2048-bit RSA client certificate for device '{dev_id}'.",
                action_taken="Certificate Registered"
            )

@app.on_event("startup")
async def startup_event():
    seed_default_devices()
    # Start background loop for device simulation
    asyncio.create_task(simulation_loop())

async def process_device_packet(
    device_id: str,
    payload_str: str,
    gateway: str,
    cert_override_invalid: bool = False
):
    """
    Core security validation pipeline representing the Edge Gateway's behavior.
    """
    # 1. Look up device and fetch its registered certificate
    device_info = db.get_device(device_id)
    
    # Check if blocked in mesh
    if mesh.is_device_blocked_in_mesh(device_id) or (device_info and device_info["status"] == "blocked"):
        db.add_audit_log(
            level="CRITICAL",
            device_id=device_id,
            gateway=gateway,
            message=f"Packet dropped: Incoming connection from {device_id} dropped by firewalls (Mesh Blacklisted).",
            payload=payload_str,
            action_taken="Packet Dropped"
        )
        return
        
    # Check if cert validity is overridden by attack
    cert_valid = False
    cert_pem = ""
    
    if device_info and not cert_override_invalid:
        cert_pem = device_info["cert_pem"]
        # Cryptographically verify the client certificate against our Root CA
        cert_valid = ca.verify_device_cert(cert_pem)
    
    firmware = device_info["firmware_version"] if device_info else "v1.0.0"
    ip_addr = device_info["ip_address"] if device_info else "192.168.10.254"
    current_trust = device_info["trust_score"] if device_info else 100
    current_status = device_info["status"] if device_info else "offline"
    
    # 2. Feed into trust evaluation engine
    new_trust, violations = trust_engine.evaluate_device_packet(
        device_id=device_id,
        payload_str=payload_str,
        cert_valid=cert_valid,
        firmware=firmware,
        ip_addr=ip_addr,
        current_trust=current_trust
    )
    
    # Save the updated trust score
    if device_info:
        db.update_device_trust(device_id, new_trust)
        
    # 3. Trigger Autonomous Incident Response Agent to decide mitigation
    action, thinking = agent.evaluate_threat_and_respond(
        device_id=device_id,
        trust_score=new_trust,
        violations=violations,
        current_status=current_status,
        gateway=gateway
    )
    
    # Execute agent actions on the Distributed Mesh
    mesh_logs = []
    if action == "BLOCK":
        mesh_logs = mesh.broadcast_block(gateway, device_id)
        # Mark as blocked
        db.update_device_status(device_id, "blocked")
    elif action == "QUARANTINE":
        mesh_logs = mesh.broadcast_quarantine(gateway, device_id)
        # Mark as restricted
        db.update_device_status(device_id, "restricted")
    elif action == "RESTORE" and current_status != "online":
        mesh_logs = mesh.broadcast_restore(gateway, device_id)
        db.update_device_status(device_id, "online")

    # 4. Form audit logs & save
    log_level = "INFO"
    if violations:
        log_level = "CRITICAL" if action == "BLOCK" else "MAJOR" if action == "QUARANTINE" else "WARNING"
        
    # Format log message
    msg = f"Validated telemetry from '{device_id}' at {gateway}. Trust score: {new_trust}."
    if violations:
        msg = f"Security Violation on '{device_id}' at {gateway}! Violations: {', '.join(violations)}."
        
    db.add_audit_log(
        level=log_level,
        device_id=device_id,
        gateway=gateway,
        message=msg,
        payload=payload_str,
        action_taken=f"{action} (Mesh synced: {len(mesh_logs)} nodes)" if mesh_logs else action
    )
    
    # Add mesh broadcast events to database audit logs
    for ml in mesh_logs:
        db.add_audit_log(
            level="WARNING",
            device_id=device_id,
            gateway="Security Mesh Sync",
            message=ml,
            action_taken="Mesh Synchronized"
        )
        
    # Broadcast event payload via WebSockets
    await broadcast_ws({
        "type": "telemetry_event",
        "device_id": device_id,
        "gateway": gateway,
        "payload": json.loads(payload_str) if not violations or "injection" not in str(violations) else {"raw": payload_str},
        "trust_score": new_trust,
        "violations": violations,
        "action": action,
        "thinking": thinking,
        "mesh_sync": mesh_logs
    })

async def simulation_loop():
    """
    Ticks every 2.5 seconds, triggering sensor readings and simulated threat payloads.
    """
    while True:
        try:
            await asyncio.sleep(2.5)
            
            # Fetch devices in database
            active_devices = db.get_devices()
            
            # Check if attack is rogue_device
            if simulator.attack_active == "rogue":
                # Simulate unknown device
                rogue_id = "sensor_unknown_99"
                payload, gw = simulator.generate_next_payload(rogue_id)
                # Rogue device lacks certificate registration
                await process_device_packet(rogue_id, payload, gw, cert_override_invalid=True)
                simulator.attack_count_left -= 1
                if simulator.attack_count_left <= 0:
                    simulator.attack_active = None
                continue
                
            for dev in active_devices:
                dev_id = dev["device_id"]
                
                # Check if we are simulating ddos flooding on this device
                is_ddos_target = (simulator.attack_active == "ddos" and simulator.attack_target == dev_id)
                cert_override = (simulator.attack_active == "invalid_cert" and simulator.attack_target == dev_id)
                
                if is_ddos_target:
                    # Flood with 20 packets in a single tick!
                    for i in range(20):
                        payload, gw = simulator.generate_next_payload(dev_id)
                        await process_device_packet(dev_id, payload, gw, cert_override_invalid=cert_override)
                    simulator.attack_count_left -= 1
                    if simulator.attack_count_left <= 0:
                        simulator.attack_active = None
                else:
                    # Normal simulation tick
                    payload, gw = simulator.generate_next_payload(dev_id)
                    await process_device_packet(dev_id, payload, gw, cert_override_invalid=cert_override)
                    
            # Check attack count decay
            if simulator.attack_active and simulator.attack_count_left > 0:
                # Decay counter for invalid cert attacks or other target-based ones
                if simulator.attack_active in ["invalid_cert"]:
                    simulator.attack_count_left -= 1
                    if simulator.attack_count_left <= 0:
                        simulator.attack_active = None
                        
            # Push global states
            await broadcast_ws({
                "type": "state_sync",
                "devices": db.get_devices(),
                "logs": db.get_audit_logs(30),
                "mesh": mesh.get_mesh_status(),
                "nis2": db.get_nis2_checklist()
            })
            
        except Exception as e:
            logger.error(f"Error in simulation loop: {e}")
            await asyncio.sleep(2)

# API Endpoints
@app.get("/api/devices")
def api_get_devices():
    return db.get_devices()

@app.get("/api/logs")
def api_get_logs():
    return db.get_audit_logs(100)

@app.get("/api/nis2")
def api_get_nis2():
    return db.get_nis2_checklist()

@app.post("/api/nis2/update")
def api_update_nis2(req: Nis2UpdateRequest):
    db.update_nis2_item(req.id, req.status, req.notes)
    return {"status": "ok"}

@app.get("/api/policies")
def api_get_policies():
    return db.get_policies()

@app.post("/api/policies/update")
def api_update_policy(req: PolicyUpdateRequest):
    db.update_policy(req.key, req.value)
    # Reload agent parameters dynamically
    if req.key == "trust_quarantine_threshold":
        agent.quarantine_threshold = int(req.value)
    elif req.key == "trust_block_threshold":
        agent.block_threshold = int(req.value)
    return {"status": "ok"}

@app.post("/api/register")
def api_register_device(req: DeviceRegisterRequest):
    # Check if already registered
    if db.get_device(req.device_id):
        raise HTTPException(status_code=400, detail="Device ID already registered")
        
    # Create cryptographic cert for this device
    cert_pem, key_pem = ca.issue_device_cert(req.device_id, expiry_days=365)
    
    # Store in database
    db.register_device(
        device_id=req.device_id,
        cert_pem=cert_pem,
        firmware=req.firmware_version,
        ip=req.ip_address,
        gateway=req.gateway_node,
        device_type=req.device_type
    )
    
    # Add to simulator device database
    simulator.add_device(
        device_id=req.device_id,
        device_type=req.device_type,
        firmware=req.firmware_version,
        ip=req.ip_address,
        gateway=req.gateway_node
    )
    
    db.add_audit_log(
        level="INFO",
        device_id=req.device_id,
        gateway=req.gateway_node,
        message=f"Manual Registration: Device '{req.device_id}' registered successfully. Issued x509 cert.",
        action_taken="Device Registered"
    )
    
    return {
        "status": "ok",
        "device_id": req.device_id,
        "cert_pem": cert_pem,
        "private_key_pem": key_pem
    }

@app.post("/api/attack")
def api_trigger_attack(req: AttackRequest):
    simulator.trigger_attack(req.attack_type, req.target_device, duration_ticks=5)
    
    # Log the simulated threat starting
    db.add_audit_log(
        level="WARNING",
        device_id=req.target_device if req.attack_type != "rogue" else "sensor_unknown_99",
        gateway="Simulation Control",
        message=f"Attack Simulation Injected: Triggering '{req.attack_type}' attack targeting '{req.target_device}'.",
        action_taken="Attack Simulation Started"
    )
    return {"status": "ok", "attack": req.attack_type, "target": req.target_device}

@app.post("/api/clear_attack")
def api_clear_attack():
    simulator.attack_active = None
    simulator.attack_target = None
    return {"status": "ok"}

@app.post("/api/override")
def api_manual_override(req: OverrideRequest):
    # Perform manual override
    device = db.get_device(req.device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
        
    mesh_logs = []
    action_taken = ""
    if req.action == "BLOCK":
        db.update_device_status(req.device_id, "blocked")
        db.update_device_trust(req.device_id, 0)
        mesh_logs = mesh.broadcast_block("Operator Console", req.device_id)
        action_taken = "Operator Blocked Device"
    elif req.action == "QUARANTINE":
        db.update_device_status(req.device_id, "restricted")
        db.update_device_trust(req.device_id, 60)
        mesh_logs = mesh.broadcast_quarantine("Operator Console", req.device_id)
        action_taken = "Operator Quarantined Device"
    elif req.action == "RESTORE":
        db.update_device_status(req.device_id, "online")
        db.update_device_trust(req.device_id, 100)
        mesh_logs = mesh.broadcast_restore("Operator Console", req.device_id)
        action_taken = "Operator Restored Device"
        
    db.add_audit_log(
        level="WARNING",
        device_id=req.device_id,
        gateway="Operator Console",
        message=f"Manual Override: Device state changed to {req.action} by administrator.",
        action_taken=action_taken
    )
    
    for ml in mesh_logs:
        db.add_audit_log(
            level="WARNING",
            device_id=req.device_id,
            gateway="Security Mesh Sync",
            message=ml,
            action_taken="Mesh Synchronized"
        )
        
    return {"status": "ok", "action": req.action}

@app.get("/api/ca/root")
def api_get_ca_root():
    return {"root_ca_pem": ca.get_root_ca_pem()}

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        # Push initial sync state on connection
        await websocket.send_json({
            "type": "state_sync",
            "devices": db.get_devices(),
            "logs": db.get_audit_logs(30),
            "mesh": mesh.get_mesh_status(),
            "nis2": db.get_nis2_checklist()
        })
        # Wait for messages (can be empty keepalives)
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if websocket in active_connections:
            active_connections.remove(websocket)
