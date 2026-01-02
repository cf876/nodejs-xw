FROM node:18-alpine

RUN apk add --no-cache curl bash

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY index.js index.html ./

RUN mkdir -p /app/tmp && chmod 777 /app/tmp

EXPOSE 7860 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:7860/ || exit 1

CMD ["node", "index.js"]
