from typing import Dict, Set, List
import time

class DistributedMesh:
    def __init__(self):
        # We simulate 3 gateway nodes
        self.gateways = ["Gateway Alpha", "Gateway Beta", "Gateway Gamma"]
        
        # Shared blocklist synchronised across the mesh (contains device_ids)
        self.shared_blocklist: Set[str] = set()
        
        # Shared quarantine list (restricted devices)
        self.shared_quarantine: Set[str] = set()
        
        # Threat intel database of synced incidents
        # Each entry: { "timestamp": float, "source_gateway": str, "device_id": str, "threat_type": str, "description": str }
        self.threat_intel_history: List[Dict] = []

    def sync_threat_alert(self, source_gateway: str, device_id: str, threat_type: str, description: str):
        """
        Receives threat telemetry from one gateway and synchronizes it to all other mesh gateways.
        """
        # Validate gateway source
        if source_gateway not in self.gateways:
            # Drop telemetry if the gateway isn't part of the mesh (prevents rogue inputs)
            return []
            
        sync_logs = []
        timestamp = time.time()
        
        # Add to local threat history
        self.threat_intel_history.append({
            "timestamp": timestamp,
            "source_gateway": source_gateway,
            "device_id": device_id,
            "threat_type": threat_type,
            "description": description
        })
        
        # Broadcast threat intel to the other nodes
        other_gateways = [g for g in self.gateways if g != source_gateway]
        for gateway in other_gateways:
            sync_logs.append(
                f"Mesh Sync: {source_gateway} broadcasted threat intel '{threat_type}' regarding {device_id} to {gateway}."
            )
            
        return sync_logs

    def broadcast_block(self, source_gateway: str, device_id: str):
        """
        Broadcasting a block action across the mesh so that all gateways block the device.
        """
        self.shared_blocklist.add(device_id)
        sync_logs = []
        other_gateways = [g for g in self.gateways if g != source_gateway]
        for gateway in other_gateways:
            sync_logs.append(
                f"Mesh Block Sync: {gateway} has blacklisted {device_id} based on {source_gateway} command."
            )
        return sync_logs

    def broadcast_quarantine(self, source_gateway: str, device_id: str):
        """
        Broadcasting a quarantine action across the mesh so that all gateways restrict the device.
        """
        self.shared_quarantine.add(device_id)
        sync_logs = []
        other_gateways = [g for g in self.gateways if g != source_gateway]
        for gateway in other_gateways:
            sync_logs.append(
                f"Mesh Quarantine Sync: {gateway} has restricted {device_id} based on {source_gateway} alert."
            )
        return sync_logs

    def broadcast_restore(self, source_gateway: str, device_id: str):
        """
        Broadcasting a recovery action across the mesh.
        """
        if device_id in self.shared_blocklist:
            self.shared_blocklist.remove(device_id)
        if device_id in self.shared_quarantine:
            self.shared_quarantine.remove(device_id)
            
        sync_logs = []
        other_gateways = [g for g in self.gateways if g != source_gateway]
        for gateway in other_gateways:
            sync_logs.append(
                f"Mesh Restore Sync: {gateway} cleared blocks for {device_id} based on {source_gateway} restoration."
            )
        return sync_logs

    def is_device_blocked_in_mesh(self, device_id: str) -> bool:
        return device_id in self.shared_blocklist

    def is_device_quarantined_in_mesh(self, device_id: str) -> bool:
        return device_id in self.shared_quarantine

    def get_mesh_status(self):
        return {
            "gateways": self.gateways,
            "blocklist": list(self.shared_blocklist),
            "quarantine": list(self.shared_quarantine),
            "threat_count": len(self.threat_intel_history)
        }
