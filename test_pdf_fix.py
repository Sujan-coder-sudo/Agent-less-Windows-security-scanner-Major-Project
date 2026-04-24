#!/usr/bin/env python3
"""Test script to verify PDF generation fixes."""

import sys
sys.path.insert(0, 'backend')

from services.pdf_service import safe_table_data, generate_pdf

# Test 1: safe_table_data function
print("=" * 60)
print("TEST 1: safe_table_data function")
print("=" * 60)

# Test empty data
data = []
result = safe_table_data(data)
print(f"Empty data: {result}")
assert result == [["No Data Available"]], "Failed: empty data"

# Test inconsistent columns
data = [["A", "B"], ["C"]]
result = safe_table_data(data)
print(f"Inconsistent cols: {result}")
assert all(len(row) == 2 for row in result), "Failed: inconsistent cols"

# Test non-list rows
data = ["just a string", ["A", "B"]]
result = safe_table_data(data)
print(f"Non-list rows: {result}")
assert all(len(row) == 2 for row in result), "Failed: non-list rows"

# Test already consistent
data = [["A", "B"], ["C", "D"]]
result = safe_table_data(data)
print(f"Consistent data: {result}")
assert all(len(row) == 2 for row in result), "Failed: consistent data"

print("✓ All safe_table_data tests passed!")

# Test 2: Generate PDF with sample data
print("\n" + "=" * 60)
print("TEST 2: PDF generation with sample data")
print("=" * 60)

test_scan = {
    "scan_id": "test-123",
    "scan_type": "os_inspection",
    "target": "localhost",
    "timestamp": "2024-01-15T10:30:00Z",
    "summary": {
        "total_checks": 13,
        "critical": 1,
        "high": 2,
        "medium": 3,
        "low": 7,
        "failed": 0
    },
    "findings": [
        {
            "category": "Firewall Status",
            "risk": "CRITICAL",
            "analysis": {
                "summary": "Windows Defender Firewall is disabled",
                "logic": "All profiles report disabled state"
            },
            "command": {
                "executed": "netsh advfirewall show allprofiles",
                "raw_output": "Domain Profile: OFF\nPrivate Profile: OFF\nPublic Profile: OFF"
            }
        },
        {
            "category": "Password Policy",
            "risk": "HIGH",
            "analysis": {
                "summary": "Password minimum length is only 0 characters",
                "logic": "Should be at least 14 per NIST guidelines"
            },
            "command": {
                "executed": "net accounts",
                "raw_output": "Minimum password length: 0"
            }
        }
    ]
}

try:
    pdf_path = generate_pdf(test_scan)
    print(f"✓ PDF generated successfully: {pdf_path}")
    
    # Verify file exists
    import os
    if os.path.exists(pdf_path):
        size = os.path.getsize(pdf_path)
        print(f"✓ PDF file exists with size: {size} bytes")
        
        # Cleanup
        os.remove(pdf_path)
        print(f"✓ Cleanup completed")
    else:
        print(f"✗ PDF file not found at: {pdf_path}")
        sys.exit(1)
        
except Exception as e:
    print(f"✗ PDF generation failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("\n" + "=" * 60)
print("ALL TESTS PASSED!")
print("=" * 60)
