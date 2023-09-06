import uvicorn
from pydantic import BaseModel
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Response, Request, HTTPException
from fastapi.responses import RedirectResponse

from fastapi_sessions.frontends.implementations import (
    SessionCookie,
    CookieParameters,
)
from fastapi_sessions.backends.implementations import InMemoryBackend
from fastapi_sessions.session_verifier import SessionVerifier

from openid.extensions import sreg, pape
from openid.consumer import consumer
from openid.store.filestore import FileOpenIDStore
from openid.store.nonce import mkNonce


SESSION_COOKIE_NAME = "pyoidconsexsid"
sessions = {}


class SessionData(BaseModel):
    username: str
    email: str
    fullname: str


cookie_params = CookieParameters()

# Uses UUID
cookie = SessionCookie(
    cookie_name="cookie",
    identifier="general_verifier",
    auto_error=True,
    secret_key="DONOTUSE",
    cookie_params=cookie_params,
)

backend = InMemoryBackend[UUID, SessionData]()


class BasicVerifier(SessionVerifier[UUID, SessionData]):
    def __init__(
        self,
        *,
        identifier: str,
        auto_error: bool,
        backend: InMemoryBackend[UUID, SessionData],
        auth_http_exception: HTTPException,
    ):
        self._identifier = identifier
        self._auto_error = auto_error
        self._backend = backend
        self._auth_http_exception = auth_http_exception

    @property
    def identifier(self):
        return self._identifier

    @property
    def backend(self):
        return self._backend

    @property
    def auto_error(self):
        return self._auto_error

    @property
    def auth_http_exception(self):
        return self._auth_http_exception

    def verify_session(self, model: SessionData) -> bool:
        """If the session exists, it is valid"""
        return True


verifier = BasicVerifier(
    identifier="general_verifier",
    auto_error=False,
    backend=backend,
    auth_http_exception=HTTPException(
        status_code=403, detail="invalid session"
    ),
)

OPENID_PROVIDER_URL = "https://login.ubuntu.com"

app = FastAPI()


async def getConsumer(request: Request):
    store = FileOpenIDStore("/tmp/openid-filestore")
    session = await getSession(request)
    return consumer.Consumer(session, store)


async def getSession(request: Request):
    # Get value of cookie header that was sent
    sid = request.cookies.get(SESSION_COOKIE_NAME, None)
    # If a session id was not set, create a new one
    if sid is None:
        # Pure pragmatism: Use function for nonce salt to generate session ID.
        sid = uuid4()
        data = SessionData(username="", email="", fullname="")
        await backend.create(sid, data)

    session = await backend.read(sid)

    return {
        "username": session.username,
        "fullname": session.fullname,
        "email": session.email,
        "id": sid,
    }


def setSessionCookie(self):
    sid = self.getSession()["id"]
    session_cookie = "%s=%s;" % (self.SESSION_COOKIE_NAME, sid)
    self.send_header("Set-Cookie", session_cookie)


@app.get("/process")
async def process(request: Request, response: Response):
    oidconsumer = await getConsumer(request)
    print(oidconsumer)
    url = "http://" + request.headers.get("Host") + "/process"
    info = oidconsumer.complete(request.query_params, url)
    print(info)
    display_identifier = info.getDisplayIdentifier()

    if info.status == consumer.FAILURE and display_identifier:
        return {"error": info.message}

    elif info.status == consumer.SUCCESS:
        sreg_resp = sreg.SRegResponse.fromSuccessResponse(info)
        username = sreg_resp.get("nickname")
        fullname = sreg_resp.get("fullname")
        email = sreg_resp.get("email")
        sid = uuid4()
        data = SessionData(username=username, email=email, fullname=fullname)
        await backend.create(sid, data)
        cookie.attach_to_response(response, sid)

        if request.query_params.get("return_url"):
            resp = RedirectResponse(request.query_params.get("return_url"))
            cookie.attach_to_response(resp, sid)
            return resp
        return {"success": "VERIFIED", "username": username}


@app.get("/verify")
async def verify(request: Request, response: Response):
    oidconsumer = await getConsumer(request)
    try:
        oid_request = oidconsumer.begin(OPENID_PROVIDER_URL)
    except consumer.DiscoveryFailure as exc:
        return {"error": exc}
    else:
        print(oid_request)

        if oid_request is None:
            return {"error": "None"}
        else:
            sreg_request = sreg.SRegRequest(
                required=["email", "nickname"],
                optional=["fullname"],
            )
            return_url_arg = request.query_params.get("return_url")
            return_url = ""
            if return_url_arg is not None:
                return_url = "?return_url=" + return_url_arg
            pape_request = pape.Request([pape.AUTH_PHISHING_RESISTANT])
            oid_request.addExtension(sreg_request)
            oid_request.addExtension(pape_request)
            redirect_url = oid_request.redirectURL(
                "http://0.0.0.0:8000",
                "http://0.0.0.0:8000/process" + return_url,
            )

            return RedirectResponse(redirect_url)


@app.get("/user", dependencies=[Depends(cookie)])
def user(session_data: SessionData = Depends(verifier)):
    if session_data is not None:
        return session_data
    return RedirectResponse("/verify?return_url=/user")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
