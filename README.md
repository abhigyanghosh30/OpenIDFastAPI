# OpenIDFastAPI

A simple webapp for testing the feasibility for integrating OpenID with FastAPI

## Pre-requisites

```console
$ pip install fastapi fastapi-sessions python3-openid pydantic
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
