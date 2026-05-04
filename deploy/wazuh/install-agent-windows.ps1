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
LogStep "Wazuh Agent 설치 (manager=${ManagerHost}:${ManagerPort}, group=${GroupName})"
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

# 4a) Sysmon 설치 — Windows 기본 process audit 은 부족. Sysmon event 1 (process
# create) 가 boan_killchain_rules.xml 의 매칭 source.
# 이미 깔려있으면 skip. config 는 SwiftOnSecurity 의 sysmonconfig-export.xml 사용
# (process create + network connect + image load 광범위 수집 — boanclaw 에 충분).
LogStep "Sysmon 설치 확인..."
$sysmonInstalled = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmonInstalled) {
    $sysmonZip = "$env:TEMP\Sysmon.zip"
    $sysmonDir = "$env:TEMP\Sysmon"
    LogStep "  download Sysmon (sysinternals)"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $sysmonZip -UseBasicParsing
    if (Test-Path $sysmonDir) { Remove-Item -Recurse -Force $sysmonDir }
    Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force
    $sysmonExe = Join-Path $sysmonDir "Sysmon64.exe"
    $configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    $configPath = "$env:TEMP\sysmonconfig.xml"
    LogStep "  download sysmon config (SwiftOnSecurity baseline)"
    Invoke-WebRequest -Uri $configUrl -OutFile $configPath -UseBasicParsing
    LogStep "  install Sysmon64 with config"
    & $sysmonExe -accepteula -i $configPath | Out-Null
} else {
    LogStep "  Sysmon64 이미 설치됨 — skip"
}

# 4b) Wazuh agent ossec.conf 에 Microsoft-Windows-Sysmon/Operational 채널 추가.
# 기본은 안 들어있어서 sysmon event 가 manager 로 안 감.
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $ossecConf) {
    $cfg = Get-Content $ossecConf -Raw
    if ($cfg -notmatch "Microsoft-Windows-Sysmon/Operational") {
        LogStep "ossec.conf 에 Sysmon eventchannel 추가"
        $sysmonBlock = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@
        # </ossec_config> 직전 삽입
        $cfg = $cfg -replace "</ossec_config>", "$sysmonBlock`n</ossec_config>"
        Set-Content -Path $ossecConf -Value $cfg -Encoding UTF8
    } else {
        LogStep "  Sysmon eventchannel 이미 등록됨"
    }
}

# 5) 서비스 시작
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
