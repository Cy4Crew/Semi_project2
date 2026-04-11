# README_OPERATIONS

이 문서는 `Semi_project2`의 **구조, 운영 흐름, 설정 파일 의미, VMware 연동 방식, 장애 확인 지점**을 자세히 설명합니다.

---

## 1. 프로젝트 구조

이 프로젝트는 단일 프로세스가 모든 분석을 처리하지 않습니다. 역할이 다음처럼 나뉩니다.

### 1-1. Docker App

루트의 `docker-compose.yml` 기준으로 앱 컨테이너가 실행됩니다.

주요 역할:

- 샘플 업로드 수신
- 정적 분석 수행
- 점수 계산 및 판정
- 필요 시 Host Bridge로 동적 분석 요청
- 결과 리포트 생성

### 1-2. Host Bridge

`host_bridge/host_bridge.py`는 **Windows 호스트에서 실행되는 FastAPI 서버**입니다.

주요 역할:

- `vmrun.exe` 호출
- 스냅샷 복구
- VM 시작 및 종료
- 공유폴더 `inbox/outbox` 작업 디렉터리 관리
- 분석 작업용 ZIP과 `job.json` 전달
- VM 결과 파일 `result.json` 회수

### 1-3. Guest Agent

`guest_tools/guest_agent.py`는 **Windows 10 VM 내부에서 실행되는 에이전트**입니다.

주요 역할:

- 공유폴더 감시
- ZIP 압축 해제
- 실행 가능한 파일 탐색
- 샘플 실행
- 프로세스/네트워크/생성 파일 흔적 수집
- `result.json` 생성 후 `outbox` 저장

---

## 2. 설정 파일 설명

### 2-1. 루트 `.env`

루트 `.env`는 **앱 컨테이너 동작 방식**을 정합니다.

주요 항목:

- `API_HOST`, `API_PORT`: 웹 앱 바인딩 주소
- `SAMPLE_TIMEOUT_SECONDS`: 샘플 처리 기본 시간
- `SANDBOX_BACKEND=auto`: 브리지 가능 시 VMware 분석 사용, 실패 시 로컬 제한 샌드박스 폴백
- `SANDBOX_BRIDGE_URL`: 호스트 브리지 주소
- `SANDBOX_VM_NAME`: 대상 VM 이름
- `SANDBOX_VM_SNAPSHOT`: 복구할 스냅샷 이름
- `SANDBOX_JOB_TIMEOUT_SECONDS`: 브리지 결과 대기 시간
- `SANDBOX_DISABLE_NETWORK=true`: 로컬 샌드박스에서 네트워크 제한
- `SANDBOX_REQUIRE_DYNAMIC_SUCCESS=false`: 동적 분석 실패 시 전체 실패로 강제하지 않음

### 2-2. `scripts/host_bridge.env.example`

이 파일은 **PowerShell 실행용 예시 설정 파일**입니다.

`scripts/run_host_bridge.ps1`는 실제로 다음 파일을 읽습니다.

```text
scripts\host_bridge.env
```

즉, PowerShell로 Host Bridge를 실행할 경우:

1. `scripts/host_bridge.env.example` 복사
2. `scripts/host_bridge.env` 생성
3. `VMX_PATH`, `VMRUN_PATH`, 필요 시 `PYTHON_BIN` 지정

### 2-3. `scripts/host_bridge.local.bat`

배치 실행용 Host Bridge는 이 파일을 직접 호출합니다.

즉,

```bat
scripts\run_host_bridge.bat
```

를 쓸 경우 실제로 중요한 파일은 `scripts\host_bridge.local.bat`입니다.

여기에 최소한 아래 값이 정확해야 합니다.

```bat
set "VMX_PATH=실제 VMX 경로"
set "VMRUN_PATH=실제 vmrun.exe 경로"
set "PYTHON_BIN=py"
```

---

## 3. VMware 연동 방식

### 3-1. `vmrun.exe`

Host Bridge는 VMware API 대신 `vmrun.exe`를 사용합니다.

코드에서 수행하는 주요 작업:

- `start <vmx>`
- `stop <vmx> soft`
- `stop <vmx> hard`
- `revertToSnapshot <vmx> <snapshot>`
- `list`

따라서 Windows 호스트에서 `vmrun.exe`가 실제로 실행 가능해야 합니다.

### 3-2. VMX 경로

Host Bridge는 대상 VM을 `.vmx` 경로로 식별합니다.

자동 탐색이 실패하거나 다른 VM을 잘못 집을 수 있으므로, 문서 기준 운영에서는 **직접 `VMX_PATH`를 고정하는 방식**이 가장 안전합니다.

### 3-3. 스냅샷 이름

기본값은 `clean`입니다.

앱과 브리지 모두 스냅샷 복구를 전제로 동작하므로, 실제 VMware 안에도 **동일 이름의 스냅샷이 반드시 있어야** 합니다.

---

## 4. 공유폴더 구조와 의미

Host Bridge 기본 작업 경로는 다음과 같습니다.

```text
host_bridge/workspace/
```

그 아래 공유폴더용 구조는 다음과 같습니다.

```text
host_bridge/workspace/shared/
├─ inbox/
└─ outbox/
```

분석 시에는 report_id 단위로 하위 폴더가 생성됩니다.

예시:

```text
shared/inbox/<report_id>/sample.zip
shared/inbox/<report_id>/job.json
shared/outbox/<report_id>/result.json
```

### 의미

- `inbox/<report_id>`: 호스트 → VM 전달 영역
- `outbox/<report_id>`: VM → 호스트 결과 반환 영역
- `job.json`: 분석 메타데이터
- `result.json`: Guest Agent 분석 결과

---

## 5. Guest Agent 상세 설명

`guest_agent.py`는 VM 안에서 다음 순서로 동작합니다.

### 5-1. 공유폴더 경로 탐색

코드는 `VM_SHARED_DIR` 환경변수를 우선 보고, 없으면 다음 후보를 순차적으로 검사합니다.

- `C:\sandbox_shared`
- `\\vmware-host\Shared Folders\sandbox_shared`
- `\\vmware-host\Shared Folders\shared`
- `Z:\sandbox_shared`
- `Z:\shared`

따라서 운영상 가장 안전한 방식은 다음 둘 중 하나입니다.

- VMware 공유 이름을 `shared` 또는 `sandbox_shared`로 맞춤
- `bootstrap_guest.ps1` 실행 시 `VM_SHARED_DIR`를 명시적으로 설정

### 5-2. 분석 대상 추출

ZIP을 안전하게 풀고, 내부 파일 중 실행 가능 후보를 선별합니다.

실행 우선순위는 코드 기준으로 다음 계열이 포함됩니다.

- `.exe`
- `.dll`
- `.ps1`
- `.bat`
- `.cmd`
- `.js`
- `.vbs`
- `.py`

### 5-3. 실행 방식

확장자별 실행 방식은 다음과 같습니다.

- `.py` → `python file.py`
- `.ps1` → `powershell -ExecutionPolicy Bypass -File file.ps1`
- `.bat`, `.cmd` → `cmd /c file`
- `.js` → `wscript //B file.js`
- `.vbs` → `cscript //B file.vbs`
- `.exe` → 직접 실행

### 5-4. 수집 정보

코드상 다음 정보가 수집됩니다.

- 실행 전후 프로세스 스냅샷
- 네트워크 연결 변화
- 생성 파일 분류
- 의심 프로세스 마커
- 타임라인 이벤트
- stdout/stderr 일부 미리보기

결과는 `result.json`으로 저장됩니다.

---

## 6. `bootstrap_guest.ps1` 설명

이 스크립트는 Guest Agent를 VM 안에 설치하고 자동 실행 등록하는 용도입니다.

기본 파라미터:

- `SharedDir`: 공유폴더 경로
- `WorkDir`: 기본 `C:\sandbox_work`
- `InstallDir`: 기본 `C:\sandbox_agent`

수행 작업:

1. 작업 폴더 생성
2. 설치 폴더 생성
3. `guest_agent.py` 복사
4. `pip` 업그레이드
5. `psutil` 설치
6. 머신 환경변수 `VM_WORK_DIR` 등록
7. 필요 시 머신 환경변수 `VM_SHARED_DIR` 등록
8. 작업 스케줄러 `SandboxGuestAgent` 생성
9. 로그온 시 자동 실행 설정
10. 즉시 작업 시작

권장 실행 예:

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap_guest.ps1 -SharedDir "\\vmware-host\Shared Folders\shared"
```

공유폴더 이름이 `sandbox_shared`라면 그 경로로 바꿔서 넣으면 됩니다.

---

## 7. Host Bridge 처리 흐름

`/submit` 요청이 들어오면 Host Bridge는 다음 순서로 처리합니다.

1. 대상 VMX 경로 결정
2. `jobs/<report_id>`, `inbox/<report_id>`, `outbox/<report_id>` 생성
3. 업로드 파일 저장
4. 샘플 ZIP을 `inbox/<report_id>`로 복사
5. `job.json` 생성
6. 스냅샷 복구
7. VM 시작
8. `result.json` 생성 대기
9. 결과 수집 후 응답 반환
10. `finally` 블록에서 VM 종료
11. 다시 스냅샷 복구
12. 임시 작업 폴더 정리

중요한 점은 **정상 종료든 실패든 마지막에는 종료와 스냅샷 복구를 시도한다는 것**입니다.

---

## 8. 헬스체크 확인 포인트

호스트 브리지가 뜬 뒤 `http://localhost:9080/health` 결과에서 반드시 확인할 항목은 다음입니다.

- `status`
- `vmrun_exists`
- `shared_dir`
- `vmx_path`
- `vmrun_path`

### 정상 예시 판단

- `status`가 `ok`
- `vmrun_exists`가 `true`
- `vmx_path`가 `null`이 아님

### 비정상 예시 판단

- `vmrun_exists: false` → VMware CLI 경로 문제
- `vmx_path: null` → VMX_PATH 미설정 또는 자동 탐색 실패

---

## 9. 로그 확인 위치

브리지 작업 로그는 다음 위치에 쌓입니다.

```text
host_bridge/workspace/logs/*.jsonl
```

여기서 확인 가능한 대표 단계:

- `vm_revert_attempt`
- `vm_revert_result`
- `vm_start_attempt`
- `vm_start_ok`
- `result_detected`
- `vm_stop_soft_attempt`
- `vm_stop_hard_attempt`
- `cleanup_path`

즉, 브리지와 VM 사이에서 어디까지 진행됐는지 이 로그로 추적할 수 있습니다.

---

## 10. 자주 발생하는 문제와 원인

### 10-1. `inbox`는 생기는데 `outbox` 결과가 없음

원인 후보:

- VM 안에서 Guest Agent가 실행되지 않음
- 공유폴더가 VM 안에서 다른 이름으로 잡힘
- `VM_SHARED_DIR`가 틀림
- `bootstrap_guest.ps1` 미실행
- `psutil` 설치 실패

확인 순서:

1. VM 안에서 `\\vmware-host\Shared Folders\shared` 또는 `sandbox_shared` 접근 확인
2. 작업 스케줄러에 `SandboxGuestAgent` 존재 여부 확인
3. `C:\sandbox_agent\guest_agent.py` 존재 여부 확인
4. VM 안에서 수동 실행 테스트

```powershell
py C:\sandbox_agent\guest_agent.py
```

### 10-2. 브리지는 뜨는데 VM이 안 켜짐

원인 후보:

- `VMRUN_PATH` 오류
- `VMX_PATH` 오류
- 스냅샷 이름 불일치
- VMware Workstation 권한 문제

확인 순서:

```bat
"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe" list
```

이 명령이 정상 동작해야 합니다.

### 10-3. VM은 켜지는데 작업이 진행되지 않음

원인 후보:

- 공유폴더가 read-only이거나 경로 불일치
- Guest Agent가 `inbox`를 못 찾음
- 샘플 압축 해제 또는 실행 중 예외 발생

확인 포인트:

- VM 안에서 `inbox/<report_id>` 폴더가 실제 보이는지
- 샘플 ZIP과 `job.json`이 들어왔는지
- `outbox/<report_id>/result.json`가 생성되는지

### 10-4. 로컬 샌드박스로 폴백됨

문서와 코드 기준으로 `SANDBOX_BACKEND=auto` 이므로, VMware 브리지가 실패하면 로컬 제한 샌드박스로 넘어갈 수 있습니다.

즉, VMware 분석 품질을 기대했다면 반드시 브리지 상태를 먼저 확인해야 합니다.

---

## 11. 운영 권장 절차

가장 안정적인 순서는 다음입니다.

1. Windows 10 VM 생성
2. VMware Tools 설치
3. VM 내부 Python 설치
4. `guest_tools` 폴더를 VM에 복사
5. `bootstrap_guest.ps1` 실행
6. 공유폴더 연결 확인
7. `clean` 스냅샷 생성
8. 루트 `.env` 생성
9. `scripts\host_bridge.local.bat` 또는 `scripts\host_bridge.env` 설정
10. Host Bridge `/health` 확인
11. `docker compose up --build` 실행
12. 테스트 ZIP 업로드

---

## 12. 이 프로젝트의 한계

코드와 기존 문서 기준으로 이 프로젝트는 **과제형 데모/프로토타입 구조**에 가깝습니다.

즉, 다음을 전제로 봐야 합니다.

- 완전한 상용 악성코드 분석 인프라는 아님
- VMware 설정 상태에 따라 동적 분석 성공 여부가 크게 달라짐
- 공유폴더, Guest Agent, 스냅샷 준비가 핵심 의존성임
- 지원되지 않는 형식이나 환경 제약 시 일부 분석은 제한적으로 동작할 수 있음

---

## 13. 제출용 문서 작성 시 강조하면 좋은 항목

보고서나 발표 문서에는 다음 포인트를 적으면 구조 설명이 명확합니다.

- 웹 앱과 샌드박스를 분리한 구조
- 호스트 브리지를 이용한 VMware 제어 방식
- 공유폴더 기반 `inbox/outbox` 전달 모델
- Guest Agent를 통한 VM 내부 실행 및 결과 수집
- 스냅샷 복구 기반 반복 분석 구조
- 브리지 실패 시 로컬 제한 샌드박스 폴백 구조

이 문서와 함께 `README.md`를 보면 설치부터 실행까지 연결해서 이해할 수 있습니다.
