def start_zap_scan(url):
    from zapv2 import ZAPv2
    import time

    zap = ZAPv2(apikey='fd3m3utqhlj2i6o3i15dvlrlh2', proxies={'http': 'http://127.0.0.1:8080'})
    scan_id = zap.ascan.scan(url)

    print(f"[+]Scan ID: {scan_id}")

    return scan_id

