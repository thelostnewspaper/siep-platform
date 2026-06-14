import time
import random
import json
from datetime import datetime
from typing import Dict, List, Callable, Optional

class DeviceSimulator:
    def __init__(self):
        # We start with default simulated devices.
        # They will be matched against DB registrations on startup/tick.
        self.devices = {
            "sensor_01": {
                "device_id": "sensor_01",
                "device_type": "Temperature Sensor",
                "firmware_version": "v2.0.1",
                "ip_address": "192.168.10.15",
                "gateway_node": "Gateway Alpha",
                "temp_base": 42.0,
                "current_val": 42.0
            },
            "sensor_02": {
                "device_id": "sensor_02",
                "device_type": "Vibration Sensor",
                "firmware_version": "v1.0.4", # Outdated firmware!
                "ip_address": "192.168.10.22",
                "gateway_node": "Gateway Beta",
                "vib_base": 0.2,
                "current_val": 0.2
            },
            "sensor_03": {
                "device_id": "sensor_03",
                "device_type": "Pressure Sensor",
                "firmware_version": "v2.0.1",
                "ip_address": "192.168.10.45",
                "gateway_node": "Gateway Gamma",
                "pres_base": 14.5,
                "current_val": 14.5
            },
            "smart_meter_01": {
                "device_id": "smart_meter_01",
                "device_type": "Smart Energy Meter",
                "firmware_version": "v2.0.1",
                "ip_address": "192.168.10.60",
                "gateway_node": "Gateway Alpha",
                "energy_base": 12500.0,
                "current_val": 12500.0
            }
        }
        
        # Threat flags injected from user actions
        self.attack_active: Optional[str] = None # Can be: "ddos", "rogue", "invalid_cert", "sql_injection", "physical_tampering"
        self.attack_target: Optional[str] = None # Which device is compromised
        self.attack_count_left: int = 0
        
    def add_device(self, device_id: str, device_type: str, firmware: str, ip: str, gateway: str):
        self.devices[device_id] = {
            "device_id": device_id,
            "device_type": device_type,
            "firmware_version": firmware,
            "ip_address": ip,
            "gateway_node": gateway,
            "temp_base": 35.0,
            "current_val": 35.0
        }

    def trigger_attack(self, attack_type: str, target_device: str, duration_ticks: int = 5):
        self.attack_active = attack_type
        self.attack_target = target_device
        self.attack_count_left = duration_ticks

    def generate_next_payload(self, device_id: str) -> tuple[str, str]:
        """
        Generates telemetry payload for a device.
        Returns (payload_json_string, gateway_receiving_it).
        Also triggers injection if this device is current attack target.
        """
        dev = self.devices.get(device_id)
        if not dev:
            # Create dummy device settings
            dev = {
                "device_id": device_id,
                "device_type": "Temperature Sensor",
                "firmware_version": "v2.0.1",
                "ip_address": "192.168.10.99",
                "gateway_node": "Gateway Alpha",
                "temp_base": 40.0,
                "current_val": 40.0
            }
            
        gw = dev["gateway_node"]
        
        # Check if we are running an attack on this device
        is_targeted = (self.attack_active and self.attack_target == device_id)
        
        if is_targeted and self.attack_active == "sql_injection":
            payload = {
                "device_id": device_id,
                "temperature": "42.0; DROP TABLE devices;--",
                "vibration": "0.15; SELECT * FROM audit_logs;",
                "timestamp": datetime.now().isoformat()
            }
            self.attack_count_left -= 1
            if self.attack_count_left <= 0:
                self.attack_active = None
            return json.dumps(payload), gw

        if is_targeted and self.attack_active == "physical_tampering":
            # Extreme readings
            payload = {
                "device_id": device_id,
                "timestamp": datetime.now().isoformat()
            }
            if "temp_base" in dev:
                payload["temperature"] = 159.4 # Way outside -40 to 110
            if "vib_base" in dev:
                payload["vibration"] = 8.7 # Way outside 0 to 4.5
            if "pres_base" in dev:
                payload["pressure"] = 99.2 # Way outside 0 to 45
            
            self.attack_count_left -= 1
            if self.attack_count_left <= 0:
                self.attack_active = None
            return json.dumps(payload), gw

        # Normal operation
        payload = {
            "device_id": device_id,
            "timestamp": datetime.now().isoformat()
        }
        
        if "temp_base" in dev:
            dev["current_val"] += random.uniform(-0.5, 0.5)
            # Clip values
            dev["current_val"] = max(10.0, min(80.0, dev["current_val"]))
            payload["temperature"] = round(dev["current_val"], 2)
            
        elif "vib_base" in dev:
            dev["current_val"] += random.uniform(-0.02, 0.02)
            dev["current_val"] = max(0.01, min(1.5, dev["current_val"]))
            payload["vibration"] = round(dev["current_val"], 3)
            
        elif "pres_base" in dev:
            dev["current_val"] += random.uniform(-0.2, 0.2)
            dev["current_val"] = max(5.0, min(30.0, dev["current_val"]))
            payload["pressure"] = round(dev["current_val"], 2)
            
        elif "energy_base" in dev:
            dev["current_val"] += random.uniform(0.1, 0.5)
            payload["energy_kwh"] = round(dev["current_val"], 1)
            
        return json.dumps(payload), gw
