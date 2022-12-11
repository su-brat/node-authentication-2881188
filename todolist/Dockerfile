# to create todolist docker image for development (since node 14 is supported)
FROM node:14.16.1
WORKDIR /app
COPY . .
RUN npm install
CMD [ "npm", "run", "dev" ]
