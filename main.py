import sqlite3
import uvicorn
from fastapi import FastAPI, Response, Depends, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from openid.extensions import sreg, pape
from openid.consumer import consumer
from openid.store.sqlstore import SQLiteStore
from openid.store.nonce import mkNonce
from uuid import uuid4

SESSION_COOKIE_NAME = "pyoidconsexsid"
sessions = {}
SESSION = None

app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="some-random-string")


OPENID_PROVIDER_URL = "https://login.ubuntu.com"
conn = sqlite3.connect('sql.db',check_same_thread=False)

def getConsumer(request: Request):
    store = SQLiteStore(conn)
    return consumer.Consumer(getSession(request), store)


def getSession(request: Request):
    global SESSION
    """Return the existing session or a new session"""
    if SESSION is not None:
        return SESSION

    # Get value of cookie header that was sent
    sid = request.cookies.get(SESSION_COOKIE_NAME, None)
    # If a session id was not set, create a new one
    if sid is None:
        # Pure pragmatism: Use function for nonce salt to generate session ID.
        sid = mkNonce(16)
        SESSION = None
    else:
        SESSION = sessions[sid]

    # If no session exists for this session ID, create one
    if SESSION is None:
        sessions[sid] = {}
        SESSION = {}

    SESSION["id"] = sid
    return SESSION

def setSessionCookie(self):
    sid = self.getSession()["id"]
    session_cookie = "%s=%s;" % (self.SESSION_COOKIE_NAME, sid)
    self.send_header("Set-Cookie", session_cookie)


@app.get("/login")
async def login():
    sreg_req = sreg.SRegRequest(
        ["email","nickname"],
        ["fullname"],
    )
    href = sreg_req.toMessage().toURL(OPENID_PROVIDER_URL)
    return {"href": href}


@app.get("/process")
def process(request: Request):
    oidconsumer = getConsumer(request)
    print(oidconsumer)
    url = "http://" + request.headers.get("Host") + "/process"
    info = oidconsumer.complete(request.query_params, url)
    print(info)
    display_identifier = info.getDisplayIdentifier()

    if info.status == consumer.FAILURE and display_identifier:
        return {"error": info.message}

    elif info.status == consumer.SUCCESS:
        sreg_resp = sreg.SRegResponse.fromSuccessResponse(info)
        pape_resp = pape.Response.fromSuccessResponse(info)
        SESSION["username"] = sreg_resp.get("nickname")
        return {"success": "VERIFIED","username":SESSION["username"]}

@app.get("/verify")
def verify(request:Request, response: Response):
    oidconsumer = getConsumer(request)
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
                required=["email","nickname"], optional=["fullname"],

            )
            pape_request = pape.Request([pape.AUTH_PHISHING_RESISTANT])
            oid_request.addExtension(sreg_request)
            oid_request.addExtension(pape_request)
            redirect_url = oid_request.redirectURL("http://0.0.0.0:8000","http://0.0.0.0:8000/process")
            
            return RedirectResponse(redirect_url)

@app.get("/user")
def user():
    if SESSION is not None:
        return {"username":SESSION["username"]}
    else:
        return RedirectResponse("/verify")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
