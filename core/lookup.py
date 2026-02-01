import requests

class VulnLookup:
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName="

    def check_vulnerabilities(self, cpe):
        """Searches the NIST's NVD for a specific CPE."""
        if not cpe:
            return []

        query = f"{cpe}"
        try:
            # Note: In a production tool, you'd want to refine this search 
            # for better accuracy. This is a broad search.
            response = requests.get(f"{self.base_url}{cpe}")
            print(f"the link:{self.base_url}{cpe}")

            if response.status_code==200:
                data = response.json().get("vulnerabilities", [])[:3]
            else:
                data = ""
            vulns = []
            for vuln in data:
                cve = vuln["cve"]

                # extract CVSS safely
                metrics = cve.get("metrics", {})
                cvss = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        cvss = metrics[key][0]["cvssData"]["baseScore"]
                        break

                vulns.append({
                    "id": cve["id"],
                    "status": cve["vulnStatus"],
                    "cvss": cvss,
                    "summary": cve["descriptions"][0]["value"]
                })

            return vulns
        except Exception as e:
            print(f"[!] Error connecting to CVE API: {e}")
            return []