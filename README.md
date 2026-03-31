# Malware Sandbox Platform

ZIP 기반 악성코드 분석 데모 시스템.  
업로드 → 분석 → 점수화 → 리포트 생성까지 자동 처리.

---

## Features

- ZIP 파일 업로드 및 검증
- 안전한 압축 해제 (zip slip 방지)
- 정적 분석 + 간단 동적 실행
- 점수 기반 악성 여부 판단
- 근거(evidence) 기반 결과 출력
- JSON 리포트 다운로드 지원

---

## Run

pip install -r requirements.txt
python run.py

---

## Docker

docker compose up --build

---

## API

- `/` : Dashboard
- `/api/samples/upload` : 샘플 업로드
- `/api/reports/` : 리포트 목록
- `/api/reports/{id}` : JSON 결과
- `/api/reports/{id}/view` : 상세 페이지
- `/api/reports/{id}/download` : 다운로드

---

## Flow

Upload → Extract → Analyze → Score → Report
