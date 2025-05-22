from zapv2 import ZAPv2
from secure.serializers import ScanSerializer
from .models import Scan
import time
zap = ZAPv2(apikey='fd3m3utqhlj2i6o3i15dvlrlh2',
            proxies={'http': 'http://127.0.0.1:8080'})


def start_zap_scan(url):
    zap.urlopen(url)
    zap.spider.scan(url)
    time.sleep(0.5)
    scan_id = zap.ascan.scan(url)

    if scan_id == 'url_not_found':
        return None

    print(f"[+]Scan ID: {scan_id} {url}")

    return scan_id


def update_scans(scans):
    for scan in scans:
        if scan['progress'] == 100:
            continue
        scan_id = scan['scan_id']
        progress = zap.ascan.status(scan_id)
        try:
            _scan = Scan.objects.get(scan_id=scan_id)
            _scan.progress = progress
            _scan.save()
        except:
            pass


def get_reports(scans):
    reports = []
    extra = {
        "critial": 0,
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
            "critial": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        alerts = zap.core.alerts(baseurl=scan_url)
        report['alerts'] = alerts

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
                report['critial'] += 1
                extra['critial'] += 1
            if alert['risk'] != "Informational":
                report['vulnerabilities'] += 1

        reports.append(report)

    return {
        "reports": reports,
        "extra": extra
    }
