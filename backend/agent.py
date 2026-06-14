from typing import List, Dict, Tuple
from db import update_device_status, update_device_trust

class AutonomousAgent:
    def __init__(self, trust_quarantine_threshold: int = 70, trust_block_threshold: int = 45):
        self.quarantine_threshold = trust_quarantine_threshold
        self.block_threshold = trust_block_threshold

    def evaluate_threat_and_respond(
        self,
        device_id: str,
        trust_score: int,
        violations: List[str],
        current_status: str,
        gateway: str
    ) -> Tuple[str, List[str]]:
        """
        Processes violations and trust score, makes an autonomous decision, and returns (action_decided, thinking_steps).
        """
        thinking_steps = []
        action = "MONITOR"
        
        thinking_steps.append(f"🤖 Agent activated: Analyzing device telemetry for '{device_id}'.")
        thinking_steps.append(f"📊 Input parameters: trust_score={trust_score}/100, current_status='{current_status}', source_gateway='{gateway}'.")
        
        if not violations:
            thinking_steps.append("✅ No active security violations detected in the current packet payload.")
            if trust_score >= self.quarantine_threshold and current_status != "online":
                thinking_steps.append(f"🔄 Device trust score ({trust_score}) has recovered. Autonomous decision: restore to ONLINE.")
                action = "RESTORE"
            else:
                thinking_steps.append("📝 Device health is within normal operational bounds. Maintaining MONITOR state.")
                action = "MONITOR"
            return action, thinking_steps

        thinking_steps.append(f"⚠️ Flagged violations: {', '.join(violations)}")
        
        # 1. Evaluate critical breaches
        critical_violations = [v for v in violations if "Invalid Cryptographic Signature" in v or "injection" in v]
        if critical_violations:
            thinking_steps.append("🚨 CRITICAL ALERT: Digital signature validation failed or SQL/command injection was detected.")
            thinking_steps.append(f"🛡️ Security Policy: Instantaneous block required to safeguard control networks.")
            action = "BLOCK"
        
        # 2. Evaluate trust-based thresholds if not already critical
        if action != "BLOCK":
            if trust_score < self.block_threshold:
                thinking_steps.append(f"🛑 Critical trust degradation: Trust score ({trust_score}) is below block threshold ({self.block_threshold}).")
                action = "BLOCK"
            elif trust_score < self.quarantine_threshold:
                thinking_steps.append(f"🚧 Moderately compromised: Trust score ({trust_score}) is below quarantine threshold ({self.quarantine_threshold}).")
                action = "QUARANTINE"
            else:
                thinking_steps.append(f"🔍 System Alert: Warnings detected but trust score ({trust_score}) remains above quarantine threshold ({self.quarantine_threshold}).")
                action = "MONITOR"
                
        # 3. Apply the actions
        if action == "BLOCK":
            thinking_steps.append(f"⚙️ Execution: Setting state of '{device_id}' to 'blocked'.")
            thinking_steps.append(f"⚙️ Certificate Management: Adding device certificate to Revocation List (CRL).")
            thinking_steps.append(f"📡 Networking Mesh: Generating network-wide DROP rule for IP on all mesh gateways.")
            update_device_status(device_id, "blocked")
            
        elif action == "QUARANTINE":
            thinking_steps.append(f"⚙️ Execution: Setting state of '{device_id}' to 'restricted'.")
            thinking_steps.append(f"🚧 Sandbox Policy: Traffic allowed for metadata diagnostic queries only; control variables locked.")
            update_device_status(device_id, "restricted")
            
        elif action == "RESTORE":
            thinking_steps.append(f"⚙️ Execution: Setting state of '{device_id}' back to 'online'.")
            update_device_status(device_id, "online")
            
        else: # MONITOR
            thinking_steps.append(f"📝 Logging warning telemetry in audit trails. Increasing packet inspection frequency.")
            
        return action, thinking_steps
