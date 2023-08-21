# seccamp-xdp test app

This is test application for XDP hands on in Security camp.
This runs at `8080` port by default.

## Run

### Native

```shell
$ go build -o app main.go
$ ./app -port <port>
```

### Docker

```
$ docker build seccamp-xdp-app:dev .
$ docker run --rm --name seccamp-xdp-app -p 8080:8080 seccamp-xdp-app:dev
```

## Endpoints

- `/`
  This endpoint returns `hello`.
- `/ping`
  This endpoint returns `pong`.
- `who`
  This endpoint returns a handling server's local address.

## Services

- HTTP server
  - at 8080
- TCP echo server
  - at 7070
- UDP server
  - at 9090
