# Semi_project2

이 프로젝트는 **Windows 호스트에서 Docker로 웹 앱을 실행**하고, **VMware Workstation의 Windows 10 가상 머신을 샌드박스**로 사용해 동적 분석을 수행하는 구조입니다.

핵심 구성은 다음과 같습니다.

- **Docker app**: 업로드, 정적 분석, 점수 산정, 리포트 제공
- **Host Bridge**: Windows 호스트에서 `vmrun.exe`로 VMware VM 제어
- **Guest Agent**: Windows 10 VM 내부에서 공유폴더 `inbox/outbox`를 감시하고 샘플을 실행한 뒤 `result.json` 생성

---

## 1. 실행 전 준비

다음 항목이 먼저 준비되어야 합니다.

- Windows 호스트 PC
- Docker Desktop
- VMware Workstation
- Windows 10 분석용 VM 1대
- VM 내부 Python 설치
- VMware Tools 설치

이 프로젝트는 **Linux Docker 컨테이너가 직접 Windows 실행 파일을 분석하는 구조가 아니라**, **호스트 브리지와 Windows 10 VM을 통해 분석을 넘기는 구조**입니다.

---

## 2. `.env` 파일 준비

프로젝트 기준으로 확인해야 할 설정 파일은 다음 두 종류입니다.

### 2-1. 앱용 `.env`

프로젝트 루트에서 `.env.example`을 복사해 `.env`를 만듭니다.

```bash
copy .env.example .env
```

기본 예시는 다음과 같습니다.

```env
API_HOST=0.0.0.0
API_PORT=8000
SAMPLE_TIMEOUT_SECONDS=5
SANDBOX_BACKEND=auto
SANDBOX_BRIDGE_URL=http://host.docker.internal:9080
SANDBOX_VM_NAME=analysis-win10
SANDBOX_VM_SNAPSHOT=clean
SANDBOX_JOB_TIMEOUT_SECONDS=180
SANDBOX_DISABLE_NETWORK=true
SANDBOX_REQUIRE_DYNAMIC_SUCCESS=false
HOST_BRIDGE_URL=http://host.docker.internal:9080
```

일반적으로 아래 항목은 반드시 확인해야 합니다.

- `SANDBOX_BRIDGE_URL`: 호스트 브리지 주소
- `SANDBOX_VM_NAME`: 분석 VM 이름
- `SANDBOX_VM_SNAPSHOT`: 사용할 스냅샷 이름
- `SANDBOX_JOB_TIMEOUT_SECONDS`: VM 분석 대기 시간

### 2-2. 호스트 브리지 설정 파일

프로젝트에는 `scripts/host_bridge.env.example` 예시 파일이 포함되어 있습니다.

```env
VMX_PATH=C:\win10x64\win10x64.vmx
VMRUN_PATH=C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
# PYTHON_BIN=py
```

다만 **현재 배치 실행 기준으로는 `scripts\run_host_bridge.bat`가 `scripts\host_bridge.local.bat`를 직접 호출**합니다. 즉, Windows CMD 배치 방식으로 실행할 경우에는 다음 파일을 실제로 맞춰야 합니다.

```bat
@echo off
set "VMX_PATH=C:\win10x64\win10x64.vmx"
set "VMRUN_PATH=C:\PROGRA~2\VMware\VMware Workstation\vmrun.exe"
set "PYTHON_BIN=py"
```

정리하면 다음과 같습니다.

- **PowerShell 실행 시**: `scripts/host_bridge.env` 방식 사용 가능
- **배치 파일 실행 시**: `scripts/host_bridge.local.bat`를 실제로 수정해야 함

가장 간단한 방법은 **`scripts\host_bridge.local.bat`의 경로를 실제 환경에 맞게 수정**하는 것입니다.

---

## 3. VMware에 Windows 10 VM 준비

### 3-1. Windows 10 VM 생성

VMware Workstation에서 Windows 10 가상 머신을 생성합니다.

권장 준비 상태는 다음과 같습니다.

- Windows 10 설치 완료
- 로그인 가능 상태
- Python 설치 완료
- VMware Tools 설치 완료
- 공유폴더 사용 가능 상태

### 3-2. VMware Tools 설치

Guest Agent가 공유폴더를 안정적으로 찾기 위해서는 **VMware Tools 설치가 사실상 필수**입니다.

VM 내부에서 공유폴더 경로는 코드상 다음 후보를 사용합니다.

- `C:\sandbox_shared`
- `\\vmware-host\Shared Folders\sandbox_shared`
- `\\vmware-host\Shared Folders\shared`
- `Z:\sandbox_shared`
- `Z:\shared`

따라서 VMware Tools가 설치되어 있어야 `\\vmware-host\Shared Folders\...` 경로가 정상 인식됩니다.

---

## 4. 공유폴더 설정

이 프로젝트는 **호스트와 VM 사이의 파일 전달을 VMware 공유폴더로 처리**합니다.

Host Bridge는 기본적으로 다음 경로 아래에 작업 폴더를 만듭니다.

- `host_bridge/workspace/shared/inbox`
- `host_bridge/workspace/shared/outbox`

VMware 공유폴더는 이 `shared` 폴더가 VM 안에서 보이도록 연결해야 합니다.

### 설정 절차

1. VMware Workstation에서 분석용 Windows 10 VM 선택
2. **VM Settings** 열기
3. **Options > Shared Folders** 이동
4. Shared Folders를 **Always enabled** 또는 활성 상태로 설정
5. 호스트의 다음 폴더를 공유로 추가
   - `프로젝트\host_bridge\workspace\shared`
6. 공유 이름은 코드 후보에 맞춰 **`shared`** 또는 **`sandbox_shared`** 중 하나로 맞추는 것이 안전합니다

VM 내부에서 아래 구조가 보여야 합니다.

```text
\\vmware-host\Shared Folders\shared\inbox
\\vmware-host\Shared Folders\shared\outbox
```

또는

```text
\\vmware-host\Shared Folders\sandbox_shared\inbox
\\vmware-host\Shared Folders\sandbox_shared\outbox
```

필요하면 VM 내부에서 직접 `C:\sandbox_shared`를 사용하도록 환경변수를 지정할 수도 있습니다.

---

## 5. `guest_agent.py`를 VM에 넣는 방법

이 프로젝트는 **VM 내부에서 `guest_tools\guest_agent.py`가 실행되어야만** 동적 분석 결과가 생성됩니다.

포함 파일:

- `guest_tools\guest_agent.py`
- `guest_tools\bootstrap_guest.ps1`

### 방법

1. 호스트 프로젝트의 `guest_tools` 폴더를 VM 안으로 복사합니다.
2. VM 안에서 PowerShell을 관리자 권한으로 엽니다.
3. `guest_tools` 폴더로 이동합니다.
4. 아래 스크립트를 실행합니다.

```powershell
powershell -ExecutionPolicy Bypass -File .\bootstrap_guest.ps1
```

이 스크립트가 수행하는 작업은 다음과 같습니다.

- `C:\sandbox_agent` 생성
- `guest_agent.py` 복사
- `psutil` 설치
- `VM_WORK_DIR` 환경변수 등록
- 필요 시 `VM_SHARED_DIR` 환경변수 등록
- 작업 스케줄러에 `SandboxGuestAgent` 등록
- 로그인 시 Guest Agent 자동 실행

성공하면 VM 내부에 다음과 같은 실행 기반이 준비됩니다.

- 작업 폴더: `C:\sandbox_work`
- 설치 폴더: `C:\sandbox_agent`
- 실행 파일: `C:\sandbox_agent\guest_agent.py`

---

## 6. 스냅샷 생성

분석 전후로 VM을 초기 상태로 되돌리기 때문에 **스냅샷 이름이 중요**합니다.

`.env` 기본값은 다음과 같습니다.

```env
SANDBOX_VM_SNAPSHOT=clean
```

따라서 VMware Workstation에서 **반드시 `clean` 이름의 스냅샷**을 만들어야 합니다.

권장 순서는 다음과 같습니다.

1. Windows 10 VM 설치 완료
2. Python 설치
3. VMware Tools 설치
4. 공유폴더 확인
5. `guest_agent.py` 등록 완료
6. 필요 프로그램 정리
7. 이 상태에서 **`clean` 스냅샷 생성**

---

## 7. 호스트 브리지 실행

Windows 호스트에서 Host Bridge를 먼저 실행합니다.

### 배치 파일 방식

```bat
scripts\run_host_bridge.bat
```

정상 실행되면 `uvicorn`이 `0.0.0.0:9080`에서 올라갑니다.

다음 주소가 정상 응답해야 합니다.

```text
http://localhost:9080/health
```

정상 응답에서 확인할 핵심 항목:

- `status: ok`
- `vmrun_exists: true`
- `vmx_path: <실제 VMX 경로>`

---

## 8. 프로젝트 실행

프로젝트 루트에서 실행합니다.

```bat
docker compose up --build
```

또는 제공된 실행 파일을 사용할 수 있습니다.

```bat
run.bat
```

`run.bat`는 다음 순서로 동작합니다.

1. 새 CMD 창에서 Host Bridge 실행
2. 현재 창에서 `docker compose up --build` 실행

웹 앱이 올라오면 업로드한 ZIP 샘플을 분석하게 됩니다.

---

## 9. 실제 동작 흐름

분석 요청 시 전체 흐름은 다음과 같습니다.

1. 웹 앱이 Host Bridge `/health` 확인
2. Host Bridge가 지정된 스냅샷으로 VM 복구
3. Host Bridge가 VM 시작
4. 업로드한 ZIP과 `job.json`을 공유폴더 `inbox/<report_id>`에 복사
5. VM 내부 `guest_agent.py`가 `inbox`를 감시하다가 작업 수행
6. 분석 결과를 `outbox/<report_id>/result.json`에 기록
7. Host Bridge가 결과를 회수
8. 분석 종료 후 VM soft stop 시도
9. 필요 시 hard stop 수행
10. 마지막으로 스냅샷 재복구

---

## 10. 실행이 안 될 때 먼저 볼 것

### `vmx_path`가 비어 있는 경우

- `VMX_PATH`가 잘못되었거나 미설정 상태입니다.
- `scripts\host_bridge.local.bat` 또는 `scripts\host_bridge.env`에서 실제 `.vmx` 경로를 맞춰야 합니다.

### `/health`는 되는데 분석이 안 되는 경우

- 공유폴더 연결 확인
- VM 내부 `guest_agent.py` 등록 여부 확인
- `clean` 스냅샷 존재 여부 확인
- VM 내부에서 `inbox/outbox` 경로가 실제로 보이는지 확인

### `inbox`만 생기고 `outbox`가 안 나오는 경우

- VM 안에서 Guest Agent가 돌지 않는 상태일 가능성이 큽니다.
- 작업 스케줄러 `SandboxGuestAgent` 실행 여부를 확인합니다.
- 필요하면 VM 내부에서 `guest_agent.py`를 직접 실행해 테스트합니다.

---

## 11. 빠른 체크리스트

아래 항목이 모두 충족되어야 VMware 동적 분석이 정상 동작합니다.

- `.env` 생성 완료
- `scripts\host_bridge.local.bat` 경로 수정 완료
- VMware Workstation 설치 완료
- Windows 10 VM 준비 완료
- VMware Tools 설치 완료
- 공유폴더 연결 완료
- `guest_agent.py` VM 내부 등록 완료
- `clean` 스냅샷 생성 완료
- `scripts\run_host_bridge.bat` 실행 완료
- `docker compose up --build` 실행 완료

상세 운영 방식과 장애 대응은 `README_OPERATIONS.md`를 참고하면 됩니다.
