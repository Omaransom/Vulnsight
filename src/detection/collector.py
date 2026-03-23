import json
import subprocess
from typing import Dict, List, Optional

from nfstream import NFStreamer

from src.core.feature_config import FEATURE_NAMES

class TrafficCollector:
    def __init__(self, interface=None, use_pcap=None):
        self.interface = interface if interface else self._auto_detect_interface()
        self.use_pcap = use_pcap

    def _get_windows_adapters(self) -> List[Dict]:
        command = (
            "Get-NetAdapter | "
            "Select-Object Name, InterfaceDescription, InterfaceGuid, Status, LinkSpeed | "
            "ConvertTo-Json -Compress"
        )
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                check=True,
            )
            output = result.stdout.strip()
            if not output:
                return []
            parsed = json.loads(output)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            return []

    @staticmethod
    def _is_virtual_interface(name: str, description: str) -> bool:
        text = f"{name} {description}".lower()
        virtual_markers = [
            "virtual",
            "vmware",
            "hyper-v",
            "vethernet",
            "loopback",
            "npcap loopback",
            "bluetooth",
            "tailscale",
            "wireguard",
            "hamachi",
            "docker",
            "wsl",
        ]
        return any(marker in text for marker in virtual_markers)

    def _auto_detect_interface(self) -> str:
        adapters = self._get_windows_adapters()
        if not adapters:
            raise RuntimeError(
                "No network adapters found. Run as Administrator or pass interface explicitly."
            )

        up_adapters = [a for a in adapters if str(a.get("Status", "")).lower() == "up"]
        candidates = up_adapters if up_adapters else adapters

        filtered = []
        for adapter in candidates:
            name = str(adapter.get("Name", ""))
            desc = str(adapter.get("InterfaceDescription", ""))
            guid = str(adapter.get("InterfaceGuid", "")).strip()
            if not guid:
                continue
            if self._is_virtual_interface(name, desc):
                continue
            filtered.append(adapter)

        selected = filtered[0] if filtered else candidates[0]
        guid = str(selected.get("InterfaceGuid", "")).strip().strip("{}")
        if not guid:
            raise RuntimeError("Could not resolve adapter GUID for traffic collection.")

        return rf"\Device\NPF_{{{guid}}}"

    def get_flows(self):
        source = self.use_pcap if self.use_pcap else self.interface

        # Reduced timeouts for faster testing
        # idle_timeout=10: If a flow is silent for 10s, it's sent to the model
        # active_timeout=60: Long flows are split every 60s so you get alerts faster
        streamer = NFStreamer(
            source=source,
            statistical_analysis=True,
            idle_timeout=10,  
            active_timeout=60,
            promiscuous_mode=True
        )

        for flow in streamer:
            # Calculate duration in seconds for rate features
            duration_s = flow.bidirectional_duration_ms / 1000.0 if flow.bidirectional_duration_ms > 0 else 0.001

            # THE 20 FEATURE MAPPING
            features = [
                flow.dst_port,                           # 1. Destination Port
                flow.bidirectional_duration_ms,          # 2. Flow Duration (ms)
                flow.src2dst_packets,                    # 3. Total Fwd Packets
                flow.dst2src_packets,                    # 4. Total Backward Packets
                flow.src2dst_bytes,                      # 5. Total Length of Fwd Packets
                flow.dst2src_bytes,                      # 6. Total Length of Bwd Packets
                flow.src2dst_max_ps,                     # 7. Fwd Packet Length Max
                flow.src2dst_min_ps,                     # 8. Fwd Packet Length Min
                flow.dst2src_max_ps,                     # 9. Bwd Packet Length Max
                flow.dst2src_min_ps,                     # 10. Bwd Packet Length Min
                flow.bidirectional_bytes / duration_s,   # 11. Flow Bytes/s
                flow.bidirectional_packets / duration_s, # 12. Flow Packets/s
                flow.bidirectional_mean_piat_ms,         # 13. Flow IAT Mean
                flow.bidirectional_max_piat_ms,          # 14. Flow IAT Max
                flow.bidirectional_min_piat_ms,          # 15. Flow IAT Min
                flow.src2dst_psh_packets,                # 16. Fwd PSH Flags
                flow.dst2src_psh_packets,                # 17. Bwd PSH Flags
                flow.src2dst_packets / duration_s,       # 18. Fwd Packets/s
                flow.dst2src_packets / duration_s,       # 19. Bwd Packets/s
                flow.bidirectional_stddev_ps             # 20. Packet Length Std
            ]

            if len(features) != len(FEATURE_NAMES):
                continue

            metadata = {
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "protocol": flow.protocol,
                "interface": source,
            }

            yield features, metadata