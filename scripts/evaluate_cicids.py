import os
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix
import seaborn as sns
from collections import defaultdict
from data.adapters.cicids2017_adapter import CICIDSAdapter
from engine.correlator import Correlator
from engine.risk_scorer import RiskScorer
import sys

def run_evaluation():
    os.makedirs("reports", exist_ok=True)
    
    adapter = CICIDSAdapter('data/adapters/label_to_attack.yaml', 'data/cicids2017.csv')
    alerts = list(adapter.stream_alerts())
    
    # Split Tune vs Test
    tune_alerts = []
    test_alerts = []
    
    for a in alerts:
        # Based on day of week: Monday/Tuesday -> Tune (0, 1)
        if a.timestamp.weekday() in [0, 1]:
            tune_alerts.append(a)
        else:
            test_alerts.append(a)

    print(f"Tune alerts: {len(tune_alerts)}, Test alerts: {len(test_alerts)}")
    
    # Process test set
    correlator = Correlator()
    incidents = correlator.correlate(test_alerts)
    scorer = RiskScorer()
    for inc in incidents:
        scorer.score_incident(inc)
    
    # Metrics on unseen test split
    # For each alert, if it is in a HIGH/CRITICAL incident, it is flagged as ATTACK. 
    # Or maybe we just predict based on the alert itself?
    # Actually, we want to evaluate the *SOC pipeline*.
    # A true positive alert is one with label != "BENIGN".
    # Did the system successfully flag it? In our system, if it generated an Incident with High/Critical severity or Risk Score > 40.
    
    y_true = []
    y_pred = []
    
    alert_to_incident = {a.alert_id: inc for inc in incidents for a in inc.alerts}
    
    class_names = list(set([a.ground_truth_label for a in test_alerts]))
    class_names.sort()
    
    # Let's map to binary: Attack or Benign for overall metrics, but we can also do multi-class for PR/Recall/F1
    for a in test_alerts:
        gt = a.ground_truth_label
        y_true.append(gt)
        
        # Did the system flag it as an attack?
        # If it's in an incident with score > 20 or severity > LOW
        inc = alert_to_incident.get(a.alert_id)
        if inc and inc.risk_score > 20:
            # System flagged as attack, but what class? The engine doesn't classify into CICIDS classes, it maps to MITRE.
            # So multi-class classification doesn't exactly make sense unless we predict binary: Attack vs Benign.
            # But prompt says: "precision, recall, F1 (per attack class)"
            # That implies we evaluate how well EACH ground truth class was detected.
            # We can use binary evaluation per class:
            # Actually sklearn classification_report with binary prediction will fail if y_true is string.
            # Let's just predict the GT label if the system correctly flagged it, else BENIGN.
            # This is a proxy for "did we catch this specific attack".
            if gt != "BENIGN":
                y_pred.append(gt)
            else:
                y_pred.append("ATTACK_FP") # False positive on benign
        else:
            y_pred.append("BENIGN")

    # Overall Binary
    y_true_bin = [1 if y != "BENIGN" else 0 for y in y_true]
    y_pred_bin = [1 if p != "BENIGN" else 0 for p in y_pred]

    # Confusion matrix
    cm = confusion_matrix(y_true_bin, y_pred_bin)
    
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Attack'], yticklabels=['Benign', 'Attack'])
    plt.title('SOC Pipeline Confusion Matrix (Test Split)')
    plt.ylabel('Ground Truth')
    plt.xlabel('Predicted')
    plt.tight_layout()
    plt.savefig('reports/confusion_matrix.png')
    
    report = classification_report(y_true, y_pred, zero_division=0)
    
    fp_rate = cm[0][1] / (cm[0][0] + cm[0][1]) if (cm[0][0] + cm[0][1]) > 0 else 0
    comp_ratio = len(test_alerts) / len(incidents) if incidents else 0
    
    results = f"""# CICIDS2017 Unseen Data Evaluation

## Splits
- **Tune Split (Monday, Tuesday)**: {len(tune_alerts)} alerts
- **Test Split (Wednesday - Friday)**: {len(test_alerts)} alerts

## Pipeline Metrics (Test Split)
- **Alert-to-Incident Compression Ratio**: {comp_ratio:.1f}x ({len(test_alerts)} alerts -> {len(incidents)} incidents)
- **False Positive Rate**: {fp_rate:.2%}

## Per-Class Performance
```text
{report}
```
"""
    with open('reports/results.md', 'w') as f:
        f.write(results)
    print("Evaluation complete. Check reports/results.md")

if __name__ == "__main__":
    run_evaluation()
