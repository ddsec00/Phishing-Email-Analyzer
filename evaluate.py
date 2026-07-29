import os
import sys
import json
from batch_analyzer import analyze_file

def calculate_metrics(tp, fp, tn, fn):
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "Total": total,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1_Score": f1
    }

def main():
    if len(sys.argv) < 2:
        print("Usage: python evaluate.py <directory>")
        sys.exit(1)
        
    directory = sys.argv[1]
    
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".eml"):
                filepath = os.path.join(root, file)
                meta_path = filepath.replace(".eml", ".meta.json")
                
                expected = "Unknown"
                if os.path.exists(meta_path):
                    with open(meta_path, "r") as f:
                        meta = json.load(f)
                        expected = meta.get("expected_classification", "Unknown").lower()
                
                if expected == "unknown":
                    continue
                    
                risk_summary = analyze_file(filepath)
                if not risk_summary:
                    continue
                
                # Assume threshold 50 for True Positive
                score = risk_summary.get("score", 0)
                is_detected_phish = score >= 50
                is_expected_phish = expected == "phishing"
                
                if is_expected_phish and is_detected_phish:
                    tp += 1
                elif is_expected_phish and not is_detected_phish:
                    fn += 1
                elif not is_expected_phish and is_detected_phish:
                    fp += 1
                elif not is_expected_phish and not is_detected_phish:
                    tn += 1

    metrics = calculate_metrics(tp, fp, tn, fn)
    
    print("=" * 40)
    print(" Evaluation Results")
    print("=" * 40)
    print(f"Emails Tested:    {metrics['Total']}")
    print(f"Correct:          {tp + tn}")
    print(f"Accuracy:         {metrics['Accuracy'] * 100:.2f}%")
    print(f"Precision:        {metrics['Precision'] * 100:.2f}%")
    print(f"Recall:           {metrics['Recall'] * 100:.2f}%")
    print(f"F1 Score:         {metrics['F1_Score'] * 100:.2f}%")
    print("-" * 40)
    print(f"False Positives:  {fp}")
    print(f"False Negatives:  {fn}")
    print("=" * 40)

if __name__ == "__main__":
    main()
