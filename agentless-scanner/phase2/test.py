from runner import phase2_execute, append_scan_result

result = phase2_execute("192.168.56.10/24")
append_scan_result(result)

print("[Phase2] Scan completed and appended successfully")
