FROM node:22-alpine AS builder

WORKDIR /app
COPY package.json tsconfig.json ./
RUN npm install
COPY src/ src/
RUN npm run build

FROM node:22-alpine

RUN addgroup -S boan && adduser -S boan -G boan -u 1000
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json src/plugin.json ./
RUN chown -R boan:boan /app

USER boan
ENTRYPOINT ["node", "dist/index.js"]
