import urllib.request
import urllib.parse
import requests
import json
# import ssl


class Cve:
    def __init__(self, cve_id, description, severity, exploit_score):
        self.cve_id = cve_id
        self.description = description
        self.severity = severity
        self.exploit_score = exploit_score

    def __repr__(self):
        data = f"Cve ID: {self.cve_id}\nDescription: {self.description}\nSeverity: {self.severity}\nExploit Score: {self.exploit_score}"
        return data


end_point = "https://services.nvd.nist.gov/rest/json/cves/2.0/?"

api_key = "3659d776-1785-40e7-b75a-f44ab45b271b"

custom_header = {
    "apiKey": api_key
}

payload = {"resultsPerPage": "10"}


def fetch_cve(end_point, payload, custom_header):
    response = requests.get(end_point, params=payload, headers=custom_header)
    return response.json()


fetched_cves = fetch_cve(end_point, payload, custom_header)


def extract_cve_data(fetched_cves):

    vulnerabilities = fetched_cves["vulnerabilities"]
    extracted_cves = []
    for data in vulnerabilities:
        cve = data["cve"]
        cve_id = cve["id"]
        cve_description = cve["descriptions"][0]["value"]

        severity = "Unknown"
        exploit_score = 0.0

        metric = cve.get("metrics", {})

        # Error Handling Logic
        # Handling if the key cvssMetricV31 is not in the metric data
        if "cvssMetricV31" in metric and len(metric["cvssMetricV31"]) != 0:
            cvss_mv31 = metric["cvssMetricV31"][0]
            severity = cvss_mv31.get("baseSeverity", "unknown")
            exploit_score = cvss_mv31.get("exploitabilityScore", 0.0)

        elif "cvssMetricV2" in metric and len(metric["cvssMetricV2"]) != 0:
            severity = metric["cvssMetricV2"][0]["baseSeverity"]
            exploit_score = metric["cvssMetricV2"][0]["exploitabilityScore"]
        else:
            severity = "Unknown"
            exploit_score = 0.0

        cve_obj = Cve(cve_id, cve_description, severity, exploit_score)
        extracted_cves.append(cve_obj)
    return extracted_cves


extracted_cves = extract_cve_data(fetched_cves)

print(extracted_cves)


# Saving Fetched CVEs data to a cve_data.json file
with open("cve_data.json", "w") as f:
    json.dump(fetched_cves, f, indent=4)
