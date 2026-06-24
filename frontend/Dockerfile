# =============================================================================
# REXDR - Frontend
# Dockerfile
#
# Author  : Rayyan Umair
# Date    : 2026-06-20
# Stage 1 : Build the React app with Vite
# Stage 2 : Serve the static build with a minimal Node static server
# =============================================================================

FROM node:20-alpine AS build

WORKDIR /app

COPY package.json .
RUN npm install

COPY . .
RUN npm run build

FROM node:20-alpine

LABEL maintainer="Rayyan Umair <rayyanxumair@gmail.com>"
LABEL description="REXDR Frontend"
LABEL version="1.0.0"

WORKDIR /app

RUN apk add --no-cache curl

RUN npm install -g serve

COPY --from=build /app/dist ./dist

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000 || exit 1

CMD ["serve", "-s", "dist", "-l", "3000"]