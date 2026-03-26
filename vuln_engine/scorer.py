def calculate_risk(findings):
    score_map = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 2
    }

    total_score = 0

    for f in findings:
        risk = f.get("risk", "Low")
        total_score += score_map.get(risk, 1)

    if findings:
        avg_score = total_score / len(findings)
    else:
        avg_score = 0

    return round(avg_score, 2)
