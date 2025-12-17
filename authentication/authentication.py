import socketserver
from util.request import Request
from util.router import Router
from util.hello_path import hello_path

from util.response import Response
from util.database import cHATDATA, uSERDATA

from util.auth import extract_credentials, validate_password
import bcrypt
from util.database import rEGISTERDATA
import uuid

import pyotp
from dotenv import load_dotenv
import os
load_dotenv()
REDIRECTURI = "http://localhost:8081/authcallback"
GITHUBCLIENTID = os.environ["GITHUB_CLIENT_ID"]
GITHUBCLIENTSECRET = os.environ["GITHUB_CLIENT_SECRET"]

import time
import socket

import datetime
from datetime import timezone
import jwt
import requests

with open ("jwtRS256.key", "r") as fp:
    pRIVATEKEY = fp.read()

def cREATEJWT(uSERNAME, uSERID):
    '''Make a payload and encode like in the documentation'''
    payload = {
        "id": uSERID,
        "username": uSERNAME,
        "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(seconds=60*60)}
    encoded = jwt.encode(payload, pRIVATEKEY, algorithm="RS256")

    return encoded



def mOVETOREGISTRATION(request, handler):
    try:

        '''Read the template and register'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/register.html", "r")) as fP:
            rEGISTERHTML = fP.read()

        '''Replace the content with the register content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", rEGISTERHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOLOGIN(request, handler):
    try:

        '''Read the template and login'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/login.html", "r")) as fP:
            lOGINHTML = fP.read()

        '''Replace the content with the login content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", lOGINHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def pOSTREGISTRATION(request, handler):

    '''Get the username and password that the user inputed'''
    [uSERNAME, pASSWORD, tOTP] = extract_credentials(request)

    '''No username inputed'''
    if not uSERNAME:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("no username")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''No password inputed'''
    if not pASSWORD:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("no password")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Password that the user inputed is invalid'''
    if not validate_password(pASSWORD):
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("password is invalid")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the users username and password from the database'''
    uSERusername = rEGISTERDATA.find_one({"username": uSERNAME})

    '''The inputed username is already in the database'''
    if uSERusername:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("the username already exists")


        handler.request.sendall(rESPONCE.to_data())

        return


    '''Make a userid'''
    uSERID = uuid.uuid4().hex



    '''Turn the password string into bytes'''
    pASSWORDBYTES = pASSWORD.encode()

    '''Make a bcrypt salt'''
    bCRYPTSALT = bcrypt.gensalt()

    '''Hash and salt the password'''
    hASHEDPASSWORD = bcrypt.hashpw(pASSWORDBYTES, bCRYPTSALT)

    '''Turn the hashed bytes into a string'''
    hASHEDpasswordSTRING = hASHEDPASSWORD.decode()


    '''Add the user to the registered database'''
    rEGISTERDATA.insert_one({"id": uSERID, "username": uSERNAME, "password": hASHEDpasswordSTRING, "hashedAuthenticationToken": None})


    rESPONCE = Response()
    rESPONCE.set_status(200, "OK")
    rESPONCE.text("registered ok")

    handler.request.sendall(rESPONCE.to_data())


def pOSTLOGIN(request, handler):

    '''Get the username and password and tOTP that the user inputed'''
    [uSERNAME, pASSWORD, tOTP] = extract_credentials(request)

    '''No username inputed'''
    if not uSERNAME:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("no username")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''No password inputed'''
    if not pASSWORD:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("no password")

        handler.request.sendall(rESPONCE.to_data())

        return


    '''Get the users username and password from the database'''
    uSERusername = rEGISTERDATA.find_one({"username": uSERNAME})

    '''The inputed username is not in the database'''
    if not uSERusername:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("the username is not in database")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the stored password hash from the database and turn the hash into bytes'''
    sTOREPASSWORDDHASH = uSERusername.get("password").encode()

    '''Check if the stored password hash matches the inputed password'''
    cHECKIFPASSWORDSMATCH = bcrypt.checkpw(pASSWORD.encode(), sTOREPASSWORDDHASH)

    if cHECKIFPASSWORDSMATCH == False:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("passwords don't match")

        handler.request.sendall(rESPONCE.to_data())

        return



    '''Check if the user has two factor authrization on'''
    sECRET = uSERusername.get("twoFactorSecret")

    if sECRET:

        '''The user has two factor authrization on but didnt give a code'''
        if not tOTP:
            rESPONCE = Response()

            rESPONCE.set_status(401, "Unauthorized")
            rESPONCE.text("no code")

            handler.request.sendall(rESPONCE.to_data())

            return


        if (pyotp.TOTP(sECRET).verify(tOTP) == False):

            rESPONCE = Response()

            rESPONCE.set_status(401, "Unauthorized")
            rESPONCE.text("Not the right code")

            handler.request.sendall(rESPONCE.to_data())

            return


    jWT = cREATEJWT(uSERusername["username"], uSERusername["id"])


    '''Turn the users session author into their username'''
    sESSION = request.cookies.get("session")

    if sESSION:

        '''Use the session to get the author from the database'''
        sESSIONauthor = uSERDATA.find_one({"session": sESSION})

        if sESSIONauthor:

            '''Store only the author'''
            aUTHOR = sESSIONauthor.get("author")

            '''Update the name of the chat authors if the username if different'''
            if aUTHOR != uSERusername["username"]:

                '''Update the name of the chats with author to the username'''
                aUTHORSMESSAGES = cHATDATA.find({"author": aUTHOR})

                for aUTHORSMESSAGE in aUTHORSMESSAGES:

                    cHATDATA.update_one({"id": aUTHORSMESSAGE["id"]}, {"$set": {"author": uSERusername["username"]}})

                '''Update the name of the author to the username'''
                uSERDATA.update_one({"session": sESSION}, {"$set": {"author": uSERusername["username"]}})


    rESPONCE = Response()

    rESPONCE.set_status(200, "OK")
    rESPONCE.text("logged in")

    '''Set cookie with an authentication token as auth_token, have httponly true, set the max age to a hour'''
    cOOKIE = "auth_token=" + jWT + "; HttpOnly; Max-Age=" + str(60 * 60) + "; Path=/; Secure"
    rESPONCE.headers({"Set-Cookie": cOOKIE})

    handler.request.sendall(rESPONCE.to_data())


def gETLOGOUT(request, handler):

    '''Clear the cookie'''
    rESPONCE = Response()

    '''Redirect to login'''
    rESPONCE.set_status(302, "Found")
    rESPONCE.headers({"Location": "/login"})

    cOOKIE = "auth_token=; HttpOnly; Max-Age=0; Path=/; Secure"
    rESPONCE.headers({"Set-Cookie": cOOKIE})

    handler.request.sendall(rESPONCE.to_data())


def gETAUTHGITHUB(request, handler):

    '''AUTTHENTICATION URL for github'''
    aUTHENTICATIONURL = "https://github.com/login/oauth/authorize"

    '''Use state to stop XSRF attacks'''
    sTATE = uuid.uuid4().hex

    '''Make the location that is going to be redirected to'''
    lOCATION = aUTHENTICATIONURL + "?response_type=code" + "&client_id=" + GITHUBCLIENTID + "&redirect_uri=" + REDIRECTURI + "&scope=read:user%20user:email%20repo&state=" + sTATE



    rESPONCE = Response()

    '''Make the cookie that is going to be sent to the user that we can verify later. Use a 300 status code and Location header to redirect'''
    rESPONCE.set_status(303, "Temporary Redirect")

    hEADERCOOKIES = {"Set-Cookie": "state=" + sTATE + "; HttpOnly; Max-Age=" + str(60 * 10) + "; Path=/; Secure", "Location": lOCATION}
    rESPONCE.headers(hEADERCOOKIES)


    rESPONCE.text("temporary redirect to github")

    handler.request.sendall(rESPONCE.to_data())


def gETAUTHCALLBACK(request, handler):

    '''Get the code and state'''
    cODE = ""
    sTATE = ""

    if "?" in request.path:

        pARTS = request.path.split("?", 1)

        qUERY = pARTS[1]

        for pART in qUERY.split("&"):

            '''Get the value of code and store it in cODE and get the value of state and store it in sTATE'''
            if pART.startswith("code="):
                cODE = pART.split("=", 1)[1]

            elif pART.startswith("state="):
                sTATE = pART.split("=", 1)[1]

    '''No code found'''
    if (cODE == ""):
        rESPONCE = Response()

        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("no code found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''No state found'''
    if (sTATE == ""):
        rESPONCE = Response()

        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("no state found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the users cookie state'''
    uSERCOOKIESTATE = request.cookies.get("state")

    '''No user state found'''
    if (uSERCOOKIESTATE == None):
        rESPONCE = Response()

        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("no state found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''If the users cooke state and the state doesnt match they are not authorized'''
    if (uSERCOOKIESTATE != sTATE):
        rESPONCE = Response()

        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("wrong state")

        handler.request.sendall(rESPONCE.to_data())

        return


    '''Use the link to exchange the code for a acess token'''
    pOSTEDACCESSTOKENURL = "https://github.com/login/oauth/access_token"

    '''Tell github to give the responce in json format'''
    hEADER = {"Accept": "application/json"}

    '''Give the client_id, client_secret, code, and redirect_uri'''
    dATATOGIVE = {"client_id": GITHUBCLIENTID, "client_secret" : GITHUBCLIENTSECRET, "code" : cODE, "redirect_uri" : REDIRECTURI}


    aCCESSTOKEN = ""

    '''Use try and expect because we are tickling json'''
    try:

        '''Send the post request to github and get the json responce'''
        aCCESSTOKENFROMCODE = requests.post(pOSTEDACCESSTOKENURL, headers=hEADER, data=dATATOGIVE)

        '''Turn the json responce into python dictonarry'''
        tOKENJSON = aCCESSTOKENFROMCODE.json()

        '''Get the access token from the python dictonarry'''
        aCCESSTOKEN = tOKENJSON.get("access_token")

        '''Github didnt give an access token'''
        if aCCESSTOKEN == None:

            rESPONCE = Response()

            rESPONCE.set_status(401, "Unauthorized")
            rESPONCE.text("no access token")

            handler.request.sendall(rESPONCE.to_data())

            return

    except Exception:
        rESPONCE = Response()

        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("json went wrong")

        handler.request.sendall(rESPONCE.to_data())

        return


    '''Use the access token to get the github user and email'''
    gITHUBHEADERS = {"Authorization": "Bearer " + aCCESSTOKEN}

    gITHUBUSERJSON = requests.get("https://api.github.com/user", headers=gITHUBHEADERS)

    '''Turn the github responce to a python dictonarry'''
    gITHUBUSER = gITHUBUSERJSON.json()


    '''Get the users username and email'''
    gITHUBUSERLOGIN = gITHUBUSER.get("login")

    gITHUBUSEREMAIL = gITHUBUSER.get("email")

    '''If there is an email make it the username. If there isnt a email make the username the login'''
    gITHUBUSERUSERNAME = ""

    if (gITHUBUSEREMAIL):

        gITHUBUSERUSERNAME = gITHUBUSEREMAIL

    else:

        gITHUBUSERUSERNAME = gITHUBUSERLOGIN

    '''The username is still empty so there wasnt a gITHUBUSEREMAIL or gITHUBUSERLOGIN'''
    if (gITHUBUSERUSERNAME == ""):
        rESPONONCE = Response()

        rESPONONCE.set_status(404, "Not Found")
        rESPONONCE.text("no github login or email found")

        handler.request.sendall(rESPONONCE.to_data())

        return

    '''Check if the user is in the database'''
    uSERexistsINresgisterDATABASE = rEGISTERDATA.find_one({"username": gITHUBUSERUSERNAME})

    '''User does not exist in the database so we can add them'''
    if not uSERexistsINresgisterDATABASE:

        '''Make a id for this user'''
        uSERID = uuid.uuid4().hex

        '''Add the user to the database'''
        rEGISTERDATA.insert_one({"id": uSERID, "username": gITHUBUSERUSERNAME, "password": None, "hashedAuthenticationToken": None})



    '''Get the users inforamtion'''
    uSERINFORMATION = rEGISTERDATA.find_one({"username": gITHUBUSERUSERNAME})

    jWT = cREATEJWT(uSERINFORMATION["username"], uSERINFORMATION["id"])

    rESPONCE = Response()

    '''Use a 300 status code and Location header to redirect. Set cookie with an authentication token as auth_token, have httponly true, set the max age to a hour. Clear the state'''
    lOCATION = "/settings"

    rESPONCE.set_status(303, "Temporary Redirect")

    '''Set cookie with an authentication token as auth_token, have httponly true, set the max age to a hour'''
    hEADECOOKIES = {"Location": lOCATION, "Set-Cookie": "auth_token=" + jWT + "; HttpOnly; Max-Age=" + str(60 * 60) + "; Path=/; Secure, state=; Max-Age=0; Path=/; Secure"}
    rESPONCE.headers(hEADECOOKIES)

    rESPONCE.text("Logged in with github")

    handler.request.sendall(rESPONCE.to_data())


class MyTCPHandler(socketserver.BaseRequestHandler):
    aCTIVECLIENTLIST = []

    def __init__(self, request, client_address, server):
        self.router = Router()
        self.router.add_route("GET", "/hello", hello_path, True)
        # TODO: Add your routes here


        self.router.add_route("GET", "/register", mOVETOREGISTRATION, True)
        self.router.add_route("GET", "/login", mOVETOLOGIN, True)
        self.router.add_route("POST", "/register", pOSTREGISTRATION, True)
        self.router.add_route("POST", "/login", pOSTLOGIN, True)
        self.router.add_route("GET", "/logout", gETLOGOUT, True)
        self.router.add_route("GET", "/authgithub", gETAUTHGITHUB, True)
        self.router.add_route("GET", "/authcallback", gETAUTHCALLBACK, True)


        super().__init__(request, client_address, server)

    def handle(self):

        '''Make the set timeout to 1 seconds so if no data is received in 1 seconds stop'''
        self.request.settimeout(1.0)

        '''Make the set total buffering for header and body 3 seconds'''
        bUFFERINGtimeout = 3
        bODYSTARTTIME = time.time()

        received_data = b""

        while b"\r\n\r\n" not in received_data:
            '''If the total time for buffering has been more than 3 seconds stop'''
            if ((time.time() - bODYSTARTTIME) > bUFFERINGtimeout):
                return

            '''Try to read 2048 bytes and if timeout continue'''
            try:
                received_dataPART = self.request.recv(2048)

            except socket.timeout:
                continue

            '''If there was no received part something was not right'''
            if not received_dataPART:
                return

            '''Add the part to the total received bytes'''
            received_data = received_data + received_dataPART

        '''Get the index of \r\n\r\n'''
        hEADERSEND = received_data.find(b"\r\n\r\n")

        if hEADERSEND == -1:
            return

        '''Get the index where the header ends'''
        hEADERSEND = hEADERSEND + len(b"\r\n\r\n")

        '''Use hEADERSEND to get the hEADERBYTES and bODYBYTES'''
        hEADERBYTES = received_data[:hEADERSEND]
        bODYBYTES = received_data[hEADERSEND:]

        '''Turn the header bytes into text'''
        hEADERSTEXT = hEADERBYTES.decode()

        '''Store the content length'''
        cONTENTLENGTH = 0

        '''Split on each \r\n to get each header text line'''
        for hTL in hEADERSTEXT.split("\r\n"):
            if hTL.startswith("Content-Length"):

                '''Split the content length key and its value'''
                cONTENTLENGTHandVALUE = hTL.split(":",1)
                '''Get the content length value and strip spaces'''
                cONTENTLENGTHVALUE = cONTENTLENGTHandVALUE[1].strip()
                '''Turn the content length value from a string into an int'''
                cONTENTLENGTH = int(cONTENTLENGTHVALUE)

        '''If there is no body then buffering is done'''
        if cONTENTLENGTH == 0:
            self.request.settimeout(None)
            '''Combine the header bytes and the body bytes'''
            hEADERandBODYbytes = hEADERBYTES + bODYBYTES

            request = Request(hEADERandBODYbytes)

            self.router.route_request(request, self)
            return

        bODYTIMEOUT = 3

        '''Keep reading until the entire body is complete'''
        while len(bODYBYTES) < cONTENTLENGTH:

            '''If the total time for buffering has been more than 3 seconds stop'''
            if ((time.time() - bODYSTARTTIME) > bODYTIMEOUT):
                return

            '''Try to read 2048 bytes and if timeout continue'''
            try:
                bODYBYESPART = self.request.recv(2048)

            except socket.timeout:
                continue

            '''If there was no body part something was not right'''
            if not bODYBYESPART:
                return

            '''Add the part to the total body bytes'''
            bODYBYTES = bODYBYTES + bODYBYESPART

        self.request.settimeout(None)

        '''Combine the header bytes and the body bytes'''
        hEADERandBODYbytes = hEADERBYTES + bODYBYTES

        request = Request(hEADERandBODYbytes)

        self.router.route_request(request, self)


def main():
    host = "0.0.0.0"
    port = 8081
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    server.serve_forever()

if __name__ == "__main__":
    main()