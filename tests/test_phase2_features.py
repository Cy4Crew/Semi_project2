from app.services.family_classifier import classify_family
from app.services.whitelist_service import evaluate_benign_indicators


def test_whitelist_detects_benign_package_markers():
    result = evaluate_benign_indicators({"file": "src/requirements.txt", "decoded_texts": ["fastapi\nuvicorn\npydantic"]})
    assert result["benign_strength"] >= 1
    assert result["benign_hits"]


def test_family_classifier_prefers_ransomware_on_strong_signals():
    info = classify_family([
        {"file": "payload.exe", "suspected_family": ["ransomware"], "yara_matches": ["ransomware_family"], "summary_reasons": ["ransom note txt"]}
    ], {"ransomware_signal": True})
    assert info["primary_family"] == "ransomware"
    assert info["confidence"] in {"medium", "high"}
