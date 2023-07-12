FROM golang:1.20.5

WORKDIR /work

COPY main.go main.go
COPY go.mod go.mod

RUN go build -o app main.go 

EXPOSE 8080
ENTRYPOINT [ "/work/app" ]
