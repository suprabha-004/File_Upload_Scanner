def risk_score(ext_flag, vt_stats, content_flags):
    score = 0

    # Extension risk
    if ext_flag:
        score += 30

    # VirusTotal handling
    if vt_stats:
        if vt_stats.get("status") == "Not Found":
            score += 20   # ⚠️ unknown file → moderate risk
        else:
            score += vt_stats.get('malicious', 0) * 10
            score += vt_stats.get('suspicious', 0) * 5

    # Content analysis
    score += len(content_flags) * 15

    # Final classification
    if score > 70:
        return "High Risk", score
    elif score > 40:
        return "Medium Risk", score
    else:
        return "Low Risk", score