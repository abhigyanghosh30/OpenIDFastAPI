# OpenIDFastAPI

A simple webapp for testing the feasibility to

## Installation

```console
$ pip install fastapi
```

You will also need an ASGI server, for production such as <a href="https://www.uvicorn.org" class="external-link" target="_blank">Uvicorn</a> or <a href="https://github.com/pgjones/hypercorn" class="external-link" target="_blank">Hypercorn</a>.

```console
$ pip install "uvicorn[standard]"
```

## Run

```console
$ uvicorn main:app --reload
```

The app also runs with the default VSCode debugger

