FROM node:16-alpine as builder

ENV NODE_ENV build

USER root
WORKDIR /temp/app/

COPY . /temp/app/

RUN npm i \
    && npm run build

# ---

FROM node:16-alpine

ENV NODE_ENV production

WORKDIR /usr/src/app

COPY --from=builder /temp/app/package*.json /usr/src/app
COPY --from=builder /temp/app/node_modules/ /usr/src/app/node_modules/
COPY --from=builder /temp/app/dist/ /usr/src/app/dist/
COPY --from=builder /temp/app/prisma/ /usr/src/app/prisma/

EXPOSE 5000

CMD ["npm", "run", "start:migrate:prod"]