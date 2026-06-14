import time
import re
import json

class TrustEngine:
    def __init__(self):
        # In-memory store for tracking device message timestamps to analyze traffic frequency
        # device_id -> list of timestamps (float)
        self.message_history = {}
        
    def evaluate_device_packet(
        self,
        device_id: str,
        payload_str: str,
        cert_valid: bool,
        firmware: str,
        ip_addr: str,
        current_trust: int
    ) -> tuple[int, list[str]]:
        """
        Evaluates a device's message packet and returns (new_trust_score, list_of_violations).
        Trust score is bounded between 0 and 100.
        """
        violations = []
        deductions = 0
        
        # 1. Cryptographic Authentication check
        if not cert_valid:
            violations.append("Invalid Cryptographic Signature / Certificate Revoked")
            return 0, violations  # Zero trust immediately
            
        # 2. Firmware Version (NIS2 supply chain check)
        # Assuming latest secure firmware is >= v2.0.0
        if firmware.startswith("v1."):
            deductions += 10
            violations.append("Outdated Firmware Version (v1.x detected, requires update)")
            
        # 3. Payload size check (DDoS or buffer overflow vectors)
        payload_size = len(payload_str.encode('utf-8'))
        if payload_size > 1000:
            deductions += 15
            violations.append(f"Excessive packet size: {payload_size} bytes (potential buffer overflow/exfiltration)")
            
        # 4. Message Frequency Check (DDoS Detection)
        now = time.time()
        if device_id not in self.message_history:
            self.message_history[device_id] = []
        self.message_history[device_id].append(now)
        
        # Keep only the last 1 minute of timestamps
        self.message_history[device_id] = [t for t in self.message_history[device_id] if now - t <= 60]
        
        msg_count_last_min = len(self.message_history[device_id])
        if msg_count_last_min > 60: # More than 1 packet per second on average
            deductions += 25
            violations.append(f"Excessive transmission rate: {msg_count_last_min} msgs/min (DDoS Flooding)")
        elif msg_count_last_min > 30: # Moderate warning
            deductions += 10
            violations.append(f"High transmission rate: {msg_count_last_min} msgs/min")
            
        # 5. Payload content and injection inspection
        try:
            payload = json.loads(payload_str)
            
            # Check for SQL Injection patterns or shell injections
            # Look at all string values in the payload
            injection_pattern = re.compile(
                r"(UNION\s+SELECT|SELECT\s+.*\s+FROM|DROP\s+DATABASE|DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO|' OR '1'='1|--|rm\s+-rf|chmod\s+\+x)",
                re.IGNORECASE
            )
            for k, v in payload.items():
                if isinstance(v, str) and injection_pattern.search(v):
                    deductions += 60
                    violations.append(f"Malicious command injection payload detected in field '{k}'")
                    
            # 6. Physical Sensor Integrity Check (plausible values check)
            # Temperature sensor checks (plausible range: -20C to 100C)
            if "temperature" in payload:
                temp = float(payload["temperature"])
                if temp > 110.0 or temp < -40.0:
                    deductions += 20
                    violations.append(f"Physical anomaly: Temperature reading of {temp}°C is outside plausible bounds")
            
            # Vibration checks (plausible range: 0.0g to 5.0g)
            if "vibration" in payload:
                vib = float(payload["vibration"])
                if vib > 4.5 or vib < 0.0:
                    deductions += 20
                    violations.append(f"Physical anomaly: Vibration reading of {vib}g is outside plausible bounds")

            # Pressure checks (plausible range: 0.0 bar to 50.0 bar)
            if "pressure" in payload:
                pres = float(payload["pressure"])
                if pres > 45.0 or pres < 0.0:
                    deductions += 20
                    violations.append(f"Physical anomaly: Pressure reading of {pres} bar is outside plausible bounds")
                    
        except json.JSONDecodeError:
            deductions += 30
            violations.append("Malformed JSON structure (invalid serial payload)")
            
        # Calculate new score (decay or recover slowly if no violations)
        if not violations:
            # Gradually restore trust score up to 100 (recover 2 points per clean packet)
            new_trust = min(100, current_trust + 2)
        else:
            new_trust = max(0, current_trust - deductions)
            
        return new_trust, violations
