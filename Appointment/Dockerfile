FROM node:24-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev && npm cache clean --force
COPY . .
RUN chown -R node:node /app
USER node
EXPOSE 8004
CMD ["node", "index.js"]