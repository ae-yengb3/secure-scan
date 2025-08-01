from zapv2 import ZAPv2
from secure.serializers import ScanSerializer
import nmap
from urllib.parse import urlparse
import ipaddress
import requests
from .models import Scan
import time
zap = ZAPv2(apikey='fd3m3utqhlj2i6o3i15dvlrlh2',
            proxies={'http': 'http://127.0.0.1:8080'})

api_key = ""


def start_zap_scan(url):
    zap.urlopen(url)
    zap.spider.scan(url)
    time.sleep(0.5)
    scan_id = zap.ascan.scan(url)

    if scan_id == 'url_not_found':
        return None

    print(f"[+]Scan ID: {scan_id} {url}")

    return scan_id


def get_leaks(url: str):
    if url == "":
        return []

    type_url = get_url_type(url)

    if type_url == "Domain Name":
        parsed = urlparse(url)
        domain = parsed.hostname

        query = f"domain:{domain}"

        data = v2_search(query, 1, 100, False, False, False)
        return data.get("entries", [])

    return []


def v2_search(query: str, page: int, size: int, wildcard: bool, regex: bool, de_dupe: bool) -> dict:
    res = requests.post("https://api.dehashed.com/v2/search", json={
        "query": query,
        "page": page,
        "size": size,
        "wildcard": wildcard,
        "regex": regex,
        "de_dupe": de_dupe,
    }, headers={
        "Content-Type": "application/json",
        "DeHashed-Api-Key": api_key,
    })
    return res.json()


def get_url_type(url: str):
    try:
        # Ensure URL has a scheme so urlparse works properly
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        hostname = urlparse(url).hostname

        # Try parsing the hostname as an IP address
        ipaddress.ip_address(hostname)
        return "IP Address"
    except ValueError:
        return "Domain Name"
    except Exception as e:
        return f"Error: {e}"


def update_scans(scans):
    for scan in scans:
        if scan['progress'] == 100:
            continue
        scan_id = scan['scan_id']
        try:
            progress = zap.ascan.status(scan_id)
            print(progress)
        except:
            print("Error: ", scan_id)
            progress = 100

        try:
            _scan = Scan.objects.get(scan_id=scan_id)
            _scan.progress = progress
            _scan.save()
        except:
            pass


def get_reports(scans):
    reports = []
    extra = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    for i, scan in enumerate(scans):
        scan_url = scan['url']
        report = {
            "url": scan_url,
            "alerts": [],
            "id": i,
            "vulnerabilities": 0,
            "progress": scan['progress'],
            "start_time": scan['start_time'],
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0
        }

        try:
            alerts = zap.core.alerts(baseurl=scan_url)
            report['alerts'] = alerts
        except Exception as e:
            print("Error: ", e)
            alerts = []
            report['alerts'] = []

        leaks = scan.get('leak_data', [])

        for leak in leaks:
            alert = structure_data(leak)

            alerts.append(alert)

        for alert in alerts:
            if alert['risk'] == "High":
                report['high'] += 1
                extra['high'] += 1
            elif alert['risk'] == "Medium":
                report['medium'] += 1
                extra['medium'] += 1
            elif alert['risk'] == "Low":
                report['low'] += 1
                extra['low'] += 1
            elif alert['risk'] == "Critical":
                report['critical'] += 1
                extra['critical'] += 1
            elif alert['risk'] == "Informational":
                report['informational'] += 1
            if alert['risk'] != "Informational":
                report['vulnerabilities'] += 1

        reports.append(report)

    return {
        "reports": reports,
        "extra": extra
    }


def structure_data(raw_data: dict) -> dict:
    blueprint = {
        "sourceid": "",
        "other": "",
        "method": "",
        "evidence": "",
        "pluginid": "",
        "cweid": "",
        "confidence": "",
        "wascid": "",
        "description": "",
        "messageid": "",
        "url": "",
        "reference": "",
        "solution": "",
        "alert": "",
        "param": "",
        "attack": "",
        "name": "",
        "risk": "Low",
        "id": ""
    }

    def has(key): return key in raw_data and raw_data[key]

    result = {}
    for key in blueprint:
        result[key] = str(raw_data.get(key, "")
                          ) if key in raw_data else blueprint[key]

    if "id" in raw_data:
        result["id"] = str(raw_data["id"])
    if "name" in raw_data:
        result["name"] = raw_data["name"][0] if isinstance(
            raw_data["name"], list) else raw_data["name"]
    if "url" in raw_data:
        result["url"] = raw_data["url"][0] if isinstance(
            raw_data["url"], list) else raw_data["url"]

    # Fields detected
    leaked_items = []

    field_mapping = {
        "email": "email address",
        "username": "username",
        "password": "password",
        "hashed_password": "hashed password",
        "ip_address": "IP address",
        "dob": "date of birth",
        "license_plate": "license plate",
        "address": "physical address",
        "phone": "phone number",
        "company": "company name",
        "social": "social media handle",
        "cryptocurrency_address": "cryptocurrency address",
        "database_name": "database name"
    }

    for field, label in field_mapping.items():
        if has(field):
            leaked_items.append(label)

    # Description: summarize types of data leaked
    if leaked_items:
        leaked_text = ", ".join(leaked_items[:-1])
        if len(leaked_items) > 1:
            leaked_text += f", and {leaked_items[-1]}"
        else:
            leaked_text = leaked_items[0]

        result[
            "description"] = f"The following types of sensitive information were exposed: {leaked_text}."
    else:
        result["description"] = "Sensitive information was detected."

    # Alert summary
    result["alert"] = "Data Exposure for: " + \
        (", ".join(leaked_items[:3]) +
         ("..." if len(leaked_items) > 3 else ""))

    # Attack field (optional)
    if has("password"):
        result["attack"] = "Credential leak detected"
    elif has("hashed_password"):
        result["attack"] = "Hashed credentials exposed"

    if has("ip_address"):
        result["param"] = "IP address"

    # Name
    result["name"] = generate_name(
        leaked_items, raw_data.get("email", [""])[0])

    # Solution
    result["solution"] = generate_solution(leaked_items)

    # Reference
    result["confidence"] = "High"

    # Risk score
    risk_score = 0
    for sensitive_field in ["password", "hashed_password", "email", "ip_address", "dob", "cryptocurrency_address"]:
        if has(sensitive_field):
            risk_score += 1

    if risk_score >= 5:
        result["risk"] = "Critical"
    elif risk_score >= 3:
        result["risk"] = "High"
    elif risk_score >= 2:
        result["risk"] = "Medium"
    else:
        result["risk"] = "Low"

    return result


def generate_name(leaked_items: list, email: str) -> str:
    if "password" in leaked_items:
        return f"Password Leak for {email}"
    elif "hashed password" in leaked_items:
        return f"Hashed Credentials Leak for {email}"
    elif "IP address" in leaked_items:
        return f"IP Address Exposure for {email}"
    elif "license plate" in leaked_items:
        return f"License Plate Exposure for {email}"
    elif "cryptocurrency address" in leaked_items:
        return f"Crypto Address Leak for {email}"
    elif "date of birth" in leaked_items:
        return f"DOB Exposure for {email}"
    elif "phone number" in leaked_items:
        return f"Phone Number Exposure for {email}"
    else:
        return f"Personal Data Exposure for {email}"


def generate_solution(leaked_items: list) -> str:
    parts = []

    if "password" in leaked_items:
        parts.append(
            "Reset all exposed passwords immediately and enforce strong password policies."
        )
    if "hashed password" in leaked_items:
        parts.append(
            "Evaluate the strength of the hashing algorithm. If weak or unsalted, rehash all credentials with a secure algorithm like bcrypt or Argon2."
        )
    if "email address" in leaked_items:
        parts.append(
            "Monitor for phishing campaigns targeting exposed email addresses, and notify affected users."
        )
    if "IP address" in leaked_items:
        parts.append(
            "Check for unauthorized access attempts from exposed IPs and consider geoblocking or rate limiting."
        )
    if "date of birth" in leaked_items:
        parts.append(
            "Treat affected accounts as high-risk and consider additional verification steps."
        )
    if "license plate" in leaked_items:
        parts.append(
            "Ensure vehicle-related systems do not store PII without proper encryption and access controls."
        )
    if "phone number" in leaked_items:
        parts.append(
            "Advise affected users to be alert for SIM swapping and social engineering attacks."
        )
    if "physical address" in leaked_items:
        parts.append(
            "Notify users about the exposure and recommend reviewing physical security or identity monitoring services."
        )
    if "cryptocurrency address" in leaked_items:
        parts.append(
            "Warn users of targeted scams and phishing attempts related to their exposed wallet address."
        )
    if "social media handle" in leaked_items:
        parts.append(
            "Advise users to review privacy settings and monitor for impersonation attempts."
        )
    if "database name" in leaked_items:
        parts.append(
            "Ensure databases are not exposed over the internet and are protected by strong access controls and firewall rules."
        )

    # Fallback solution if no sensitive types are detected
    if not parts:
        parts.append(
            "Review system configurations and data exposure points to identify and secure leaks.")

    return " ".join(parts)
