# Malware Sandbox Platform - Operations Guide

이 문서는 시스템 동작 방식과 내부 구조를 설명한다.

---

## 1. System Overview

이 시스템은 업로드된 ZIP 파일을 분석하여 악성 여부를 판단한다.

전체 흐름:

1. ZIP 업로드
2. 안전 검증 및 압축 해제
3. 정적 분석 수행
4. 제한된 환경에서 동적 실행
5. 로그 및 행위 수집
6. 점수 계산
7. 리포트 생성

---

## 2. System Architecture

구성 요소:

- API Server: 업로드 및 결과 조회 처리
- Worker: 분석 작업 수행
- Analyzer: 정적/동적 분석 로직
- Database: 작업 상태 및 결과 저장

데이터 흐름:

Upload → API → Queue(DB) → Worker → Analyzer → DB → API Response

---

## 3. Database Overview

주요 테이블:

- samples: 업로드된 파일 정보
- reports: 분석 결과
- trace_queue: 작업 큐 (worker가 소비)

주의:
- trace_queue가 없으면 worker 실행 시 오류 발생

---

## 4. Security Controls

### Upload 제한
- ZIP 파일만 허용
- Content-Type 검사
- 최대 업로드 크기 제한
- 최대 파일 개수 제한
- 압축 해제 후 총 크기 제한

### ZIP 보안
- Zip Slip 공격 차단
- 경로 검증 수행

---

## 5. Analysis Pipeline

### Static Analysis
- 파일 구조 분석
- 문자열 추출
- 의심 패턴 탐지

### Dynamic Analysis
- 제한된 환경에서 실행
- stdout / stderr 수집
- 프로세스 상태 기록
- 타임아웃 처리

---

## 6. Scoring System

점수는 다음 요소 기반:

- 의심 문자열
- 실행 결과
- 행위 로그
- 파일 구조

출력:
- 총 점수
- 세부 breakdown
- 주요 evidence

---

## 7. Report Lifecycle

queued → running → done / failed

---

## 8. API Details

POST /api/samples/upload

GET /api/reports/
GET /api/reports/{id}
GET /api/reports/{id}/view
GET /api/reports/{id}/download

---

## 9. Runtime Logs

- stdout
- stderr
- 실행 프로세스 정보
- 분석 단계 로그
- timeout 여부

---

## 10. Common Errors & Fixes

### 1. relation "trace_queue" does not exist
원인:
- DB 초기화 안됨

해결:
```
python -m app.init_db
```

---

### 2. Internal Server Error (JSON parse error)

원인:
- API가 JSON 대신 문자열/에러 반환

해결:
- API 응답 Content-Type 확인
- frontend에서 JSON.parse 전 응답 검증

---

## 11. Execution Environment

권장 환경: Docker

실행:

```
docker compose up --build
```

설명:
- API, DB, Worker 분리 실행
- 격리된 환경에서 분석 수행

주의:
- 로컬 실행 시 악성코드 실행 위험 존재
- 반드시 테스트 환경에서 실행

---

## 12. Execution Notes

- 실행은 완전한 sandbox가 아님 (경량 환경)
- 실제 악성코드 실행 시 주의 필요
- 테스트용 샘플 권장

---

## 13. Best Practice

- 반드시 격리된 환경에서 실행
- Docker 사용 권장
- 외부 네트워크 차단 환경 권장
