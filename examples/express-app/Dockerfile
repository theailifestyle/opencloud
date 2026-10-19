FROM node:22-alpine
WORKDIR /app
COPY package.json .
RUN npm install --omit=dev --no-audit --no-fund
COPY server.js .
USER node
ENV PORT=3000
CMD ["node", "server.js"]
