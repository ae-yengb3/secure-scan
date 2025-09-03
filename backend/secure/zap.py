from zapv2 import ZAPv2
from secure.serializers import ScanSerializer
import nmap
from urllib.parse import urlparse
import ipaddress
import requests
from .models import Scan, ScanResult
import time
import os
from datetime import datetime
import threading
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


zap = ZAPv2(apikey=os.getenv('ZAP_API_KEY'),
            proxies={'http': 'http://127.0.0.1:8080'})

api_key = os.getenv('DEHASHED_API_KEY', '')

def get_alerts(target: str, scan_id: str):
    alerts = zap.core.alerts(baseurl=target)
    scan = Scan.objects.get(scan_id=scan_id)
    
    for alert in alerts:
        # Use ZAP's pluginid + messageid as unique identifier
        unique_id = f"{alert.get('pluginId', '')}-{alert.get('messageId', '')}"
        
        # Check if this alert already exists for this scan
        if not ScanResult.objects.filter(scan=scan, unique_id=unique_id).exists():
            ScanResult.objects.create(
                scan=scan,
                unique_id=unique_id,
                alert_name=alert.get('name', ''),
                risk=alert.get('risk', 'Low'),
                confidence=alert.get('confidence', ''),
                url=alert.get('url', ''),
                description=alert.get('description', ''),
                solution=alert.get('solution', ''),
                reference=alert.get('reference', ''),
                evidence=alert.get('evidence', ''),
                attack=alert.get('attack', ''),
                param=alert.get('param', '')
            )

def send_scan_update(user_id, scan_id, progress, remark):
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"user_{user_id}",
        {
            'type': 'scan_progress_update',
            'scan_id': scan_id,
            'progress': progress,
            'remark': remark
        }
    )

def run_scans(scan_id: str):
    scan = Scan.objects.get(scan_id=scan_id)

    scan.start_time = datetime.now()
    scan.save()

    # start with a spider scan
    print(f"Starting spider scan for {scan.url}")
    _scan_id = zap.spider.scan(scan.url)
    while (int(zap.spider.status(_scan_id)) < 100):
        progress = int(zap.spider.status(_scan_id))
        print(f"Spider progress: {progress}%")
        scan.remark = "Spider scan in progress"
        scan.progress = progress
        scan.save()
        send_scan_update(scan.user.id, scan_id, progress, "Spider scan in progress")
        get_alerts(scan.url, scan_id)
        time.sleep(2)

    print(f"Spider scan completed for {scan.url}")

    # start with an active scan
    print(f"Starting active scan for {scan.url}")
    _scan_id = zap.ascan.scan(scan.url)
    while (int(zap.ascan.status(_scan_id)) < 100):
        progress = int(zap.ascan.status(_scan_id))
        print(f"Active scan progress: {progress}%")
        scan.remark = "Active scan in progress"
        scan.progress = progress
        scan.save()
        send_scan_update(scan.user.id, scan_id, progress, "Active scan in progress")
        get_alerts(scan.url, scan_id)
        time.sleep(2)

    print(f"Active scan completed for {scan.url}")
    
    get_alerts(scan.url, scan_id)

    scan.progress = 100
    scan.remark = "Scan completed"
    scan.end_time = datetime.now()
    scan.save()
    send_scan_update(scan.user.id, scan_id, 100, "Scan completed")


def start_zap_scan(url: str, user) -> str:
    scan_model = ScanSerializer(
        data={'user': user.id, 'url': url, "start_date": datetime.now()})

    if scan_model.is_valid():
        scan_model.save()

        id = scan_model.data['scan_id']

        t = threading.Thread(target=run_scans, args=(id,))
        t.start()

    return id


def run_leak_scan(scan_id: str):
    scan = Scan.objects.get(scan_id=scan_id)

    scan.start_time = datetime.now()
    scan.save()

    url = scan.url
    send_scan_update(scan.user.id, scan_id, 10, "Starting leak scan")

    type_url = get_url_type(url)
    if type_url == "Domain Name":
        parsed = urlparse(url)
        domain = parsed.hostname

        query = f"domain:{domain}"
        send_scan_update(scan.user.id, scan_id, 30, "Searching for data leaks")

        data = v2_search(query, 1, 100, False, False, False)
        entries = data.get("entries", [])
        
        send_scan_update(scan.user.id, scan_id, 70, "Processing leak data")
        
        # Process each entry and create ScanResult
        for i, entry in enumerate(entries):
            structured = structure_data(entry)
            
            # Create unique ID for this leak entry
            unique_id = f"leak-{scan_id}-{i}"
            
            # Check if this entry already exists
            if not ScanResult.objects.filter(scan=scan, unique_id=unique_id).exists():
                ScanResult.objects.create(
                    scan=scan,
                    unique_id=unique_id,
                    alert_name=structured['name'],
                    risk=structured['risk'],
                    confidence=structured['confidence'],
                    url=structured.get('url', scan.url),
                    description=structured['description'],
                    solution=structured['solution'],
                    reference=structured.get('reference', ''),
                    evidence=structured.get('evidence', ''),
                    attack=structured.get('attack', ''),
                    param=structured.get('param', '')
                )
        
    scan.progress = 100
    scan.remark = "Scan completed"
    scan.end_time = datetime.now()
    scan.save()
    send_scan_update(scan.user.id, scan_id, 100, "Leak scan completed")

def start_leak_scan(url: str, user) -> str:
    scan_model = ScanSerializer(
        data={'user': user.id, 'url': url, "start_date": datetime.now()})
    
    if scan_model.is_valid():
        scan_model.save()

        id = scan_model.data['scan_id']

        t = threading.Thread(target=run_leak_scan, args=(id,))
        t.start()

    return id

def run_hybrid_scan(scan_id: str):
    scan = Scan.objects.get(scan_id=scan_id)
    scan.start_time = datetime.now()
    scan.save()
    
    send_scan_update(scan.user.id, scan_id, 5, "Starting hybrid scan")
    
    # Run vulnerability scan
    send_scan_update(scan.user.id, scan_id, 10, "Starting vulnerability scan")
    
    # Spider scan
    _scan_id = zap.spider.scan(scan.url)
    while (int(zap.spider.status(_scan_id)) < 100):
        progress = int(zap.spider.status(_scan_id))
        scan.progress = 10 + (progress * 0.3)  # 10-40%
        scan.remark = "Spider scan in progress"
        scan.save()
        send_scan_update(scan.user.id, scan_id, scan.progress, "Spider scan in progress")
        get_alerts(scan.url, scan_id)
        time.sleep(2)
    
    # Active scan
    _scan_id = zap.ascan.scan(scan.url)
    while (int(zap.ascan.status(_scan_id)) < 100):
        progress = int(zap.ascan.status(_scan_id))
        scan.progress = 40 + (progress * 0.3)  # 40-70%
        scan.remark = "Active scan in progress"
        scan.save()
        send_scan_update(scan.user.id, scan_id, scan.progress, "Active scan in progress")
        get_alerts(scan.url, scan_id)
        time.sleep(2)
    
    # Leak scan
    send_scan_update(scan.user.id, scan_id, 70, "Starting leak scan")
    
    type_url = get_url_type(scan.url)
    if type_url == "Domain Name":
        parsed = urlparse(scan.url)
        domain = parsed.hostname
        query = f"domain:{domain}"
        
        data = v2_search(query, 1, 100, False, False, False)
        entries = data.get("entries", [])
        
        send_scan_update(scan.user.id, scan_id, 85, "Processing leak data")
        
        for i, entry in enumerate(entries):
            structured = structure_data(entry)
            unique_id = f"leak-{scan_id}-{i}"
            
            if not ScanResult.objects.filter(scan=scan, unique_id=unique_id).exists():
                ScanResult.objects.create(
                    scan=scan,
                    unique_id=unique_id,
                    alert_name=structured['name'],
                    risk=structured['risk'],
                    confidence=structured['confidence'],
                    url=structured.get('url', scan.url),
                    description=structured['description'],
                    solution=structured['solution'],
                    reference=structured.get('reference', ''),
                    evidence=structured.get('evidence', ''),
                    attack=structured.get('attack', ''),
                    param=structured.get('param', '')
                )
    
    scan.progress = 100
    scan.remark = "Hybrid scan completed"
    scan.end_time = datetime.now()
    scan.save()
    send_scan_update(scan.user.id, scan_id, 100, "Hybrid scan completed")

def start_hybrid_scan(url: str, user) -> str:
    scan_model = ScanSerializer(
        data={'user': user.id, 'url': url, "start_date": datetime.now()})
    
    if scan_model.is_valid():
        scan_model.save()
        
        id = scan_model.data['scan_id']
        
        t = threading.Thread(target=run_hybrid_scan, args=(id,))
        t.start()
    
    return id

def get_leaks(url: str):
    if url == "":
        return []

    type_url = get_url_type(url)

    if type_url == "Domain Name":
        parsed = urlparse(url)
        domain = parsed.hostname

        query = f"domain:{domain}"

        total = 0
        data = v2_search(query, 1, 100, False, False, False)
        total = data.get("total", 0)
        total_fetched  = 100

        while total_fetched <= total:
            data = v2_search(query, 1, 100, False, False, False)
            total_fetched += 100

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
    extra = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for i, scan in enumerate(scans):
        alerts = ScanResult.objects.filter(scan_id=scan['scan_id'])
        
        report = {
            "url": scan['url'],
            "alerts": list(alerts.values()),
            "id": i,
            "vulnerabilities": 0,
            "progress": scan['progress'],
            "start_time": scan['start_time'],
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "false_positive_count": alerts.filter(marked_as_false_positive=True).count(),
            "resolved_count": alerts.filter(resolved=True).count()
        }

        for alert in alerts:
            risk = alert.risk.lower()
            if risk in report:
                report[risk] += 1
                extra[risk] = extra.get(risk, 0) + 1
            if risk != "informational":
                report['vulnerabilities'] += 1

        reports.append(report)

    return {"reports": reports, "extra": extra}


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
    email_value = raw_data.get("email", "")
    if isinstance(email_value, list):
        email_value = email_value[0] if email_value else ""
    result["name"] = generate_name(leaked_items, email_value)

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
