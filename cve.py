import requests

def get_cve(service, version):
    try:
        query = f"{service} {version}"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"

        r = requests.get(url, timeout=5)
        data = r.json()

        vulns = []

        for item in data.get("vulnerabilities", [])[:3]:
            cve_id = item["cve"]["id"]

            try:
                cvss = item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
            except:
                cvss = 0

            vulns.append({
                "cve": cve_id,
                "cvss": cvss
            })

        return vulns

    except:
        return []
