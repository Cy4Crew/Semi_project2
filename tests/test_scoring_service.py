from app.services.scoring_service import calculate_score


def test_behavioral_signals_outweigh_static_only():
    files = [{
        "file": "payload.exe",
        "summary_reasons": ["contains remote thread pattern"],
        "yara_matches": ["generic_malware"],
        "suspected_family": ["rat"],
        "malware_type_tags": ["rat"],
        "score": 55,
        "evidence_items": [],
    }]
    dynamic_result = {
        "archive_member_exec_count": 1,
        "network_trace": {"endpoints": [{"host": "evil.test", "port": 443}]},
        "exec_signal": True,
    }
    verdict = calculate_score(files, dynamic_result)
    assert verdict["score"] >= 40
    assert verdict["verdict"] in {"suspicious", "malicious"}
