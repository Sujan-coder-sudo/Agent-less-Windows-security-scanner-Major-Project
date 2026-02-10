from runner import phase2_execute, append_scan_result

result = phase2_execute("127.0.0.1")
append_scan_result(result)

print("[Phase2] Scan completed and appended successfully")
