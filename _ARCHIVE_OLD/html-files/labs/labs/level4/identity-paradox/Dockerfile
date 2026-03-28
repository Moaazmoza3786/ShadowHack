FROM node:14-alpine
WORKDIR /app
COPY package.json .
RUN npm install express jsonwebtoken cookie-parser body-parser
COPY server.js .
ENV FLAG="AG{W34k_JWT_S3cr3ts_Cr4ck3d}"
EXPOSE 3000
CMD ["node", "server.js"]
