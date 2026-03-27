import urllib.request, json, sys

tests = [
    ("GET", "http://localhost:5000/api/ping"),
    ("GET", "http://localhost:5000/api/health"),
    ("GET", "http://localhost:5000/api/scans"),
    ("GET", "http://localhost:5000/api/scans/latest"),
]

all_ok = True
for method, url in tests:
    try:
        r = urllib.request.urlopen(url, timeout=5)
        d = json.loads(r.read())
        print(f"OK   [{r.status}] {url}  status={d.get('status')}")
    except urllib.error.HTTPError as e:
        try:
            d = json.loads(e.read())
        except Exception:
            d = {}
        msg = d.get("message", "")
        # 404 for /latest when no scans exist is expected
        if e.code == 404 and "scans/latest" in url:
            print(f"OK   [{e.code}] {url}  (no scans yet — expected)")
        else:
            print(f"FAIL [{e.code}] {url}  {msg}")
            all_ok = False
    except Exception as ex:
        print(f"ERR  {url}  -> {ex}")
        all_ok = False

# POST validation check (invalid body)
try:
    req = urllib.request.Request(
        "http://localhost:5000/api/scan",
        data=json.dumps({"target": "bad_input!", "scan_type": "port_scan"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    r = urllib.request.urlopen(req, timeout=5)
    print(f"FAIL [POST /api/scan] should have been rejected but got {r.status}")
    all_ok = False
except urllib.error.HTTPError as e:
    if e.code == 400:
        print(f"OK   [400] POST /api/scan rejected invalid target as expected")
    else:
        print(f"FAIL [POST /api/scan] unexpected status {e.code}")
        all_ok = False
except Exception as ex:
    print(f"ERR  POST /api/scan  -> {ex}")
    all_ok = False

print()
print("=" * 40)
print("ALL CHECKS PASSED" if all_ok else "SOME CHECKS FAILED")
sys.exit(0 if all_ok else 1)
