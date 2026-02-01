import json
import os
from datetime import datetime

class DataHandler:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        # Create the reports folder if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def save_results(self, target, data):
        """Saves scan results into a timestamped JSON file."""
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M")
        filename = f"scan_{target}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        report = {
            "target network": target,
            "scan_date&time": timestamp,
            "results_count": len(data),
            "findings": data
        }

        try:
            with open(filepath, "w") as f:
                json.dump(report, f, indent=4)
            print(f"[+] Report successfully saved to: {filepath}")
            return filepath
        except Exception as e:
            print(f"[!] Failed to save report: {e}")
            return None