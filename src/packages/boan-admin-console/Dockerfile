FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
COPY scripts ./scripts
RUN npm install
COPY . .
RUN npm run build

FROM nginx:1.25-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY <<EOF /etc/nginx/conf.d/default.conf
server {
    listen 80;
    root /usr/share/nginx/html;
    index index.html;
    location /assets/ {
        try_files \$uri =404;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
    }
    location = /favicon.ico {
        try_files \$uri =404;
    }
    location / {
        try_files \$uri \$uri/ /index.html;
        # index.html 은 절대 캐시하지 말 것 — Vite 의 hashed asset 이름이
        # 매 빌드마다 바뀌므로 index.html 이 stale 이면 옛 bundle 을 계속 fetch.
        add_header Cache-Control "no-store, no-cache, must-revalidate" always;
        add_header Pragma "no-cache" always;
        expires off;
    }
    location /api/ {
        resolver 127.0.0.11 valid=5s;
        set \$upstream http://boan-sandbox:18081;
        proxy_pass \$upstream;
        # HTTP/1.1 + buffering off 로 NDJSON 스트리밍 즉시 전달 (computer-use agent).
        # HTTP/1.0 (nginx proxy_pass 기본값) 에서는 chunked 전송 미지원이라
        # 긴 스트리밍 응답이 중간에 끊김.
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_request_buffering off;
        chunked_transfer_encoding on;
        proxy_connect_timeout 3s;
        # computer-use agent 같은 장시간 스트리밍 응답 대응 (10분)
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Cookie \$http_cookie;
        proxy_pass_header Set-Cookie;
        add_header Access-Control-Allow-Origin * always;
        add_header Access-Control-Allow-Credentials true always;
    }
    location /openclaw/ {
        resolver 127.0.0.11 valid=5s;
        set \$openclaw_upstream http://boan-sandbox:18789;
        proxy_pass \$openclaw_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 3s;
        proxy_read_timeout 60s;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Content-Security-Policy;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Content-Security-Policy "default-src 'self' 'unsafe-inline' data: blob: http: https:; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https: http:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss: http: https:;" always;
    }
    location = /openclaw {
        resolver 127.0.0.11 valid=5s;
        set \$openclaw_root_upstream http://boan-sandbox:18789/openclaw;
        proxy_pass \$openclaw_root_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 3s;
        proxy_read_timeout 60s;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Content-Security-Policy;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Content-Security-Policy "default-src 'self' 'unsafe-inline' data: blob: http: https:; base-uri 'self'; object-src 'none'; frame-ancestors 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https: http:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' ws: wss: http: https:;" always;
    }
    location /remote/ {
        resolver 127.0.0.11 valid=5s;
        set \$remote_upstream boan-guacamole:8080;
        rewrite ^/remote/(.*)$ /\$1 break;
        proxy_pass http://\$remote_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_connect_timeout 5s;
        proxy_read_timeout 300s;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Content-Security-Policy;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header Content-Security-Policy "default-src 'self' 'unsafe-inline' data: blob: http: https:; base-uri 'self'; object-src 'self' blob: data: http: https:; frame-ancestors 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: http:; font-src 'self' data: https:; connect-src 'self' ws: wss: http: https:;" always;
    }
}
EOF
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
