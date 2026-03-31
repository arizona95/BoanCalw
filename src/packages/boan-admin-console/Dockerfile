FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
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
    location / {
        try_files \$uri \$uri/ /index.html;
    }
    location /api/ {
        resolver 127.0.0.11 valid=5s;
        set \$upstream http://boan-proxy:18081;
        proxy_pass \$upstream;
        proxy_connect_timeout 3s;
        proxy_read_timeout 15s;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header Cookie \$http_cookie;
        proxy_pass_header Set-Cookie;
        add_header Access-Control-Allow-Origin * always;
        add_header Access-Control-Allow-Credentials true always;
    }
}
EOF
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
