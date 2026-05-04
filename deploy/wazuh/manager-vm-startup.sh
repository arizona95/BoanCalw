#!/bin/bash
# Wazuh Manager VM startup script — GCP Compute Engine 의 startup-script metadata 로 주입.
# debian-12 base. 첫 부팅 시 docker 설치 + wazuh-manager 컨테이너 실행 + boan rules + active-response.
#
# 환경변수 (metadata 로 inject):
#   BOAN_PROXY_WEBHOOK — boan-proxy 의 webhook URL (필수)
#                        예: http://<boan-proxy public IP>:18081/api/kill-chain/event
#                        없으면 http://host.docker.internal — 의미 없으니 admin 이 metadata 로 줌.
#
# 결과: 1514/udp, 1515/tcp, 55000/tcp 가 listen 상태. firewall rule 별도 설정 필요.

set -euxo pipefail

LOG=/var/log/boan-wazuh-init.log
exec > >(tee -a "$LOG") 2>&1

WEBHOOK=$(curl -fsSL -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/boan-proxy-webhook" \
  2>/dev/null || echo "")
WEBHOOK="${WEBHOOK:-http://example.invalid:18081/api/kill-chain/event}"
BOAN_DEFAULT_EMAIL_DOMAIN=$(curl -fsSL -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/attributes/boan-default-email-domain" \
  2>/dev/null || echo "samsung.com")
export BOAN_DEFAULT_EMAIL_DOMAIN

echo "[boan-wazuh-init] starting at $(date) — webhook=$WEBHOOK"

# 1) docker + compose 설치 (debian 12).
if ! command -v docker >/dev/null 2>&1; then
  apt-get update
  apt-get install -y ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
fi

# 2) /opt/boan-wazuh — config + scripts.
mkdir -p /opt/boan-wazuh/{rules,ar}

cat > /opt/boan-wazuh/rules/boan_killchain_rules.xml <<'RULES_EOF'
__BOAN_RULES_PLACEHOLDER__
RULES_EOF

cat > /opt/boan-wazuh/ar/boan-killchain-event.sh <<'AR_EOF'
__BOAN_AR_PLACEHOLDER__
AR_EOF
chmod +x /opt/boan-wazuh/ar/boan-killchain-event.sh

cat > /opt/boan-wazuh/entrypoint-hook.sh <<'HOOK_EOF'
__BOAN_HOOK_PLACEHOLDER__
HOOK_EOF
chmod +x /opt/boan-wazuh/entrypoint-hook.sh

# 3) docker-compose.yml 생성.
cat > /opt/boan-wazuh/docker-compose.yml <<COMPOSE_EOF
services:
  wazuh-manager:
    image: wazuh/wazuh-manager:4.7.5
    container_name: boan-wazuh-manager
    restart: unless-stopped
    ulimits:
      memlock: {soft: -1, hard: -1}
      nofile: {soft: 655360, hard: 655360}
    ports:
      - "1514:1514/udp"
      - "1515:1515"
      - "55000:55000"
    environment:
      - INDEXER_URL=
      - INDEXER_USERNAME=
      - INDEXER_PASSWORD=
      - FILEBEAT_SSL_VERIFICATION_MODE=none
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=BoanWazuh2026!
      - BOAN_PROXY_WEBHOOK=${WEBHOOK}
      - BOAN_DEFAULT_EMAIL_DOMAIN=${BOAN_DEFAULT_EMAIL_DOMAIN:-samsung.com}
    volumes:
      - /opt/boan-wazuh/rules/boan_killchain_rules.xml:/boan-staging/rules/boan_killchain_rules.xml:ro
      - /opt/boan-wazuh/ar/boan-killchain-event.sh:/boan-staging/ar/boan-killchain-event.sh:ro
COMPOSE_EOF

# 4) up — image default entrypoint (/init) 그대로 사용. 그래야 cont-init.d 가 /var/ossec
# 디렉토리 (logs/archives, queue/db, etc.) 전부 정상 populate.
cd /opt/boan-wazuh
docker compose up -d

# 5) container 가 fully up + analysisd running 까지 대기 (최대 5분).
echo "[boan-wazuh-init] waiting for wazuh-manager analysisd..."
for i in \$(seq 1 60); do
    sleep 5
    if docker exec boan-wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"; then
        echo "[boan-wazuh-init] analysisd up after \$((i*5))s"
        break
    fi
done

# 6) 우리 자산 install + ossec.conf 패치 (idempotent).
docker exec boan-wazuh-manager sh -c '
    cp /boan-staging/rules/boan_killchain_rules.xml /var/ossec/etc/rules/boan_killchain_rules.xml
    cp /boan-staging/ar/boan-killchain-event.sh /var/ossec/active-response/bin/boan-killchain-event.sh
    chmod 0755 /var/ossec/active-response/bin/boan-killchain-event.sh
    chown root:wazuh /var/ossec/etc/rules/boan_killchain_rules.xml /var/ossec/active-response/bin/boan-killchain-event.sh
    if ! grep -q "boan-killchain-event" /var/ossec/etc/ossec.conf; then
        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
        awk "
            /<\\/ossec_config>/ && !done {
                print \"  <command>\"
                print \"    <name>boan-killchain</name>\"
                print \"    <executable>boan-killchain-event.sh</executable>\"
                print \"    <timeout_allowed>no</timeout_allowed>\"
                print \"  </command>\"
                print \"\"
                print \"  <active-response>\"
                print \"    <command>boan-killchain</command>\"
                print \"    <location>server</location>\"
                print \"    <rules_group>boan_killchain_match,boan_killchain_evasion,boan_killchain_pkg_install</rules_group>\"
                print \"  </active-response>\"
                print \"\"
                done = 1
            }
            { print }
        " /var/ossec/etc/ossec.conf.bak > /var/ossec/etc/ossec.conf
        /var/ossec/bin/wazuh-control restart 2>&1 | tail -5
    fi
'
echo "[boan-wazuh-init] done at \$(date)"
