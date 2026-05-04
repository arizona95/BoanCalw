#!/bin/sh
# entrypoint-hook.sh — wazuh-manager 컨테이너의 first-boot 후 우리 자산 install.
#
# 흐름:
#   1) 원래 entrypoint (/entrypoint.sh) 를 background 로 실행 → init 가 /var/ossec
#      populate 하면서 wazuh-manager 시작.
#   2) ossec.conf 가 생길 때까지 기다림.
#   3) /boan-staging 의 rule + active-response script 를 /var/ossec 의 적절한
#      위치로 복사.
#   4) ossec.conf 에 boan-killchain command + active-response 블록 idempotent 추가.
#   5) wazuh-control restart.
#   6) foreground 유지 (원래 entrypoint 가 ENTRYPOINT 였으니 wait 필요).

set -u

LOG=/var/ossec/logs/boan-init.log
mkdir -p /var/ossec/logs 2>/dev/null
log() { echo "[$(date -u +%H:%M:%S)] [boan-init] $*" | tee -a "$LOG" 2>/dev/null || echo "[boan-init] $*"; }

# 0) 미리 logs sub-directories 만들어 두기 — image 의 cont-init.d 가 ossec.conf 생성 직후
# wazuh-analysisd 시작하는데, archives/firewall/alerts dir 가 없으면 CRITICAL 종료.
# image entrypoint 와 race 라서 background loop 으로 30 초간 반복 mkdir.
mkdir -p /var/ossec/logs/archives /var/ossec/logs/firewall /var/ossec/logs/alerts /var/ossec/queue/alerts 2>/dev/null || true
(
    for i in $(seq 1 30); do
        mkdir -p /var/ossec/logs/archives /var/ossec/logs/firewall /var/ossec/logs/alerts /var/ossec/queue/alerts 2>/dev/null
        chown -R wazuh:wazuh /var/ossec/logs /var/ossec/queue 2>/dev/null
        sleep 1
    done
) &

# 1) 원래 entrypoint background.
# wazuh-manager:4.7.5 의 default ENTRYPOINT 는 /init (s6 supervisor). /entrypoint.sh 아님.
UPSTREAM=/init
[ -x /init ] || UPSTREAM=/entrypoint.sh
log "starting upstream entrypoint: $UPSTREAM"
"$UPSTREAM" "$@" &
ENTRY_PID=$!

# 2) ossec.conf populate 대기 (최대 180s).
log "waiting for /var/ossec/etc/ossec.conf to be populated..."
for i in $(seq 1 60); do
    if [ -s /var/ossec/etc/ossec.conf ]; then
        log "ossec.conf ready (size=$(wc -c < /var/ossec/etc/ossec.conf) bytes)"
        break
    fi
    sleep 3
done

if [ ! -s /var/ossec/etc/ossec.conf ]; then
    log "WARN: ossec.conf still missing after 180s — leaving upstream entrypoint to continue"
    wait "$ENTRY_PID"
    exit $?
fi

# 추가 디렉토리 보장 — wazuh-analysisd 가 logs/archives/<year>/ 자동 생성 시도하지만
# parent (logs/archives) 가 없으면 CRITICAL 종료. image entrypoint 가 일부만 populate.
mkdir -p /var/ossec/logs/archives /var/ossec/logs/alerts /var/ossec/queue/alerts
chown -R wazuh:wazuh /var/ossec/logs /var/ossec/queue 2>/dev/null || true

# 3) staging assets 복사.
if [ -f /boan-staging/rules/boan_killchain_rules.xml ]; then
    install -m 0644 /boan-staging/rules/boan_killchain_rules.xml /var/ossec/etc/rules/boan_killchain_rules.xml
    log "rule installed: /var/ossec/etc/rules/boan_killchain_rules.xml"
fi
if [ -f /boan-staging/ar/boan-killchain-event.sh ]; then
    install -m 0755 /boan-staging/ar/boan-killchain-event.sh /var/ossec/active-response/bin/boan-killchain-event.sh
    log "active-response script installed"
fi

# 4) ossec.conf 에 boan-killchain command + active-response 블록 추가 (idempotent).
# **주의**: default ossec.conf 의 example active-response 블록이 XML 코멘트로 감싸져 있어서
# `</active-response>` anchor 가 코멘트 안쪽에서 매칭됨 → 우리 블록도 코멘트 안에 묻힘.
# `</ossec_config>` (root 닫기 태그) 직전 삽입이 안전.
if grep -q "boan-killchain-event" /var/ossec/etc/ossec.conf 2>/dev/null; then
    log "ossec.conf already patched"
else
    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
    awk '
        /<\/ossec_config>/ && !done {
            print "  <command>"
            print "    <name>boan-killchain</name>"
            print "    <executable>boan-killchain-event.sh</executable>"
            print "    <timeout_allowed>no</timeout_allowed>"
            print "  </command>"
            print ""
            print "  <active-response>"
            print "    <command>boan-killchain</command>"
            print "    <location>server</location>"
            print "    <rules_group>boan_killchain_match,boan_killchain_evasion,boan_killchain_pkg_install</rules_group>"
            print "  </active-response>"
            print ""
            done = 1
        }
        { print }
    ' /var/ossec/etc/ossec.conf.bak > /var/ossec/etc/ossec.conf
    log "ossec.conf patched (active-response + command added before </ossec_config>)"

    # 5) wazuh-control restart.
    sleep 2
    /var/ossec/bin/wazuh-control restart 2>&1 | tail -5 | tee -a "$LOG" || true
fi

log "boan-init done — handing back to upstream entrypoint"

# 6) wait — entrypoint 가 foreground 유지하던 process (보통 wazuh-control 또는
# tail -f) 가 끝날 때까지.
wait "$ENTRY_PID"
exit $?
