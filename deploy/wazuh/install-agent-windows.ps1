# ══════════════════════════════════════════════════════════════════════
# BoanClaw — Wazuh Agent 설치 스크립트 (Windows)
#
# 용도:
#   관리자가 자기 Windows VM 안에서 한 번만 실행하면, 조직의
#   boan-wazuh-manager 에 등록되는 agent 가 설치된다. 그 후 Golden Image 로
#   찍으면 이 agent + 등록 정보까지 이미지에 들어가서 신규 사용자 VM 은
#   이미 agent 가 깔린 상태로 부팅된다.
#
# 사용:
#   1) 관리자 VM 에서 PowerShell (관리자 모드) 실행.
#   2) 아래 스크립트 실행:
#        PowerShell -ExecutionPolicy Bypass -File install-agent-windows.ps1 `
#          -ManagerHost 34.47.X.X      `   # Wazuh manager 공인 IP / 호스트
#          -ManagerPort 1514           `   # (기본)
#          -RegistrationPort 1515      `   # (기본)
#          -GroupName boanclaw-org     `   # (선택) 조직별 agent 그룹
#
#   3) Control Panel > Services 에서 "Wazuh" 서비스가 Running 상태인지 확인.
#   4) BoanClaw Admin Console > Authorization > Users 탭 > "🧊 내 VM 굽기"
#      클릭 → 이 agent 가 포함된 golden image 가 찍힌다.
#
# 결과:
#   - 신규 사용자 VM 이 생성되면 같은 agent 가 자동으로 매니저에 재등록.
#   - agent 는 Sysmon / Windows Event Log / File Integrity / Registry
#     Monitoring 이벤트를 manager 로 전송.
# ══════════════════════════════════════════════════════════════════════
param(
    [Parameter(Mandatory=$true)][string] $ManagerHost,
    [int] $ManagerPort = 1514,
    [int] $RegistrationPort = 1515,
    [string] $GroupName = "boanclaw-default",
    [string] $AgentVersion = "4.7.5-1"
)

$ErrorActionPreference = "Stop"
$InstallerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$AgentVersion.msi"
$InstallerPath = "$env:TEMP\wazuh-agent.msi"

function LogStep($msg) { Write-Host "[boanclaw-wazuh] $msg" }

# 1) 기존 agent 제거 (재설치 대비)
LogStep "기존 Wazuh Agent 제거 시도..."
Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue | ForEach-Object {
    Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
}
$existing = Get-WmiObject Win32_Product -Filter "Name LIKE 'Wazuh%'" -ErrorAction SilentlyContinue
foreach ($pkg in $existing) {
    LogStep "  uninstall: $($pkg.Name)"
    $pkg.Uninstall() | Out-Null
}

# 2) MSI 다운로드
LogStep "Wazuh Agent MSI 다운로드: $InstallerUrl"
Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath -UseBasicParsing

# 3) 설치 + 등록
LogStep "Wazuh Agent 설치 (manager=$ManagerHost:$ManagerPort, group=$GroupName)"
$msiArgs = @(
    "/i", "`"$InstallerPath`"",
    "/q",
    "WAZUH_MANAGER=$ManagerHost",
    "WAZUH_MANAGER_PORT=$ManagerPort",
    "WAZUH_REGISTRATION_SERVER=$ManagerHost",
    "WAZUH_REGISTRATION_PORT=$RegistrationPort",
    "WAZUH_AGENT_GROUP=$GroupName"
)
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    throw "MSI install failed with exit code $($proc.ExitCode)"
}

# 4) 서비스 시작
LogStep "Wazuh 서비스 시작..."
Start-Service -Name "Wazuh"
Start-Sleep -Seconds 3

$svc = Get-Service -Name "Wazuh" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    LogStep "✓ Wazuh Agent 설치 완료 + 서비스 Running"
} else {
    throw "Wazuh 서비스가 시작되지 않았습니다"
}

# 5) 상태 검증 — manager 로 이벤트가 흘러갈 준비
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $ossecConf) {
    LogStep "config: $ossecConf"
    Select-String -Path $ossecConf -Pattern "<address>$ManagerHost</address>" | ForEach-Object {
        LogStep "  manager address 등록 확인"
    }
}

LogStep ""
LogStep "다음 단계:"
LogStep "  1) BoanClaw Admin Console > Authorization > Users 탭"
LogStep "  2) 상단 '🧊 내 VM 굽기' 버튼 클릭"
LogStep "  3) 10-20분 뒤 신규 사용자 VM 은 이 agent 가 설치된 상태로 생성됨"
LogStep ""
LogStep "Manager 쪽 에이전트 등록 확인 (관리자 서버에서):"
LogStep "  $ docker exec boanclaw-boan-wazuh-manager-1 /var/ossec/bin/agent_control -l"
