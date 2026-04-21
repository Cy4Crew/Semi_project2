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


def test_global_dynamic_signals_do_not_promote_unmapped_file():
    files = [{
        "file": "readme.txt",
        "summary_reasons": [],
        "yara_matches": [],
        "suspected_family": [],
        "malware_type_tags": [],
        "score": 0,
        "evidence_items": [],
    }]
    dynamic_result = {
        "execution_observed": True,
        "anti_analysis_signal": True,
        "network_trace": {"endpoints": [{"host": "evil.test", "port": 443}]},
        "sysmon_summary": {
            "execution_observed": True,
            "anti_analysis_signals": [{"signal": "taskkill_taskmgr"}],
            "network_endpoints": [{"remote_ip": "1.2.3.4", "remote_port": 443}],
            "registry_changes": [{"path": "HKCU\\Software\\Test"}],
        },
        "archive_member_attempted_count": 1,
        "archive_member_success_count": 0,
    }
    verdict = calculate_score(files, dynamic_result)
    assert verdict["score"] >= 20

    from app.services.scoring_service import assess_files
    scored = assess_files({"files": files}, dynamic_result)
    assert scored[0]["final_score"] < 20
    assert scored[0]["anti_analysis"] is False
