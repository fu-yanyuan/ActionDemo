FROM golang:1.19-alpine
RUN apk add build-base

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY *.go ./
RUN go build -o /siwe

EXPOSE 8080

CMD [ "/siwe" ]