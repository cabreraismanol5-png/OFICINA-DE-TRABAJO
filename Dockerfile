# Oficina de Trabajo Virtual - Render production image v4.7.1
FROM node:20-bookworm-slim

ENV NODE_ENV=production
ENV PORT=10000
ENV HOST=0.0.0.0

WORKDIR /app

# Install production dependencies first for better Docker layer caching.
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

# Persistent SQLite data is mounted by Render at /app/data.
RUN mkdir -p /app/data

EXPOSE 10000

# Render uses the PORT environment variable; server.js binds to 0.0.0.0.
CMD ["node", "server.js"]
