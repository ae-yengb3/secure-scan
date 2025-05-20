from zapv2 import ZAPv2
from secure.serializers import ScanSerializer
from .models import Scan

zap = ZAPv2(apikey='fd3m3utqhlj2i6o3i15dvlrlh2',
            proxies={'http': 'http://127.0.0.1:8080'})


def start_zap_scan(url):
    scan_id = zap.ascan.scan(url)

    print(f"[+]Scan ID: {scan_id}")

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