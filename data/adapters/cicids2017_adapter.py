import os
import csv
import random
from datetime import datetime, timedelta
from typing import List, Dict, Generator
import yaml

from engine.models import Alert, Severity, AssetTier
from engine.mitre_mapper import TECHNIQUE_CATALOG

# For simulation if file missing
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
LABELS = ["BENIGN", "DoS Hulk", "DDoS", "PortScan", "FTP-Patator", "SSH-Patator", "Web Attack Brute Force", "Bot", "Infiltration", "Heartbleed"]

def ensure_dummy_data(csv_path: str):
    if os.path.exists(csv_path): return
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Label"])
        
        base_time = datetime(2017, 7, 3, 9, 0, 0) # A Monday
        for i in range(5):
            day_time = base_time + timedelta(days=i)
            # Monday/Tuesday = Tune, Wednesday-Friday = Test
            for j in range(200): # 200 samples per day
                ts = (day_time + timedelta(minutes=j)).strftime("%d/%m/%Y %I:%M:%S %p")
                label = "BENIGN" if random.random() < 0.6 else random.choice(LABELS[1:])
                writer.writerow([ts, f"192.168.1.{random.randint(10,50)}", f"10.0.0.{random.randint(1,5)}", 
                                 random.randint(1000, 60000), 80, 6, label])

class CICIDSAdapter:
    def __init__(self, config_path: str, csv_path: str):
        with open(config_path, 'r') as f:
            self.label_map = yaml.safe_load(f)
            
        for lbl, tech_id in self.label_map.items():
            if tech_id and tech_id not in TECHNIQUE_CATALOG:
                raise ValueError(f"Invalid Technique ID {tech_id} for label {lbl}")
                
        ensure_dummy_data(csv_path)
        self.csv_path = csv_path
        
    def stream_alerts(self) -> Generator[Alert, None, None]:
        with open(self.csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                label = row["Label"]
                tech_id = self.label_map.get(label)
                
                # Convert flow to Alert
                severity = Severity.INFO if label == "BENIGN" else Severity.HIGH
                alert_type = "NETWORK_FLOW"
                
                # Parsing timestamp "03/07/2017 09:00:00 AM" (or similar)
                try:
                    ts = datetime.strptime(row["Timestamp"], "%d/%m/%Y %I:%M:%S %p")
                except:
                    ts = datetime.utcnow()
                    
                alert = Alert(
                    id=f"cicids_{random.randint(10000,99999)}",
                    timestamp=ts,
                    source="cicids2017",
                    type=alert_type,
                    rule_name=label,
                    severity=severity,
                    description=f"Flow labeled as {label}",
                    source_ip=row["Source IP"],
                    destination_ip=row["Destination IP"],
                    username=None,
                    hostname=None,
                    command_line=None,
                    process_name=None,
                    asset_tier=AssetTier.STANDARD,
                    mitre_technique_id=tech_id
                )
                alert.ground_truth_label = label # attach for evaluation
                yield alert

