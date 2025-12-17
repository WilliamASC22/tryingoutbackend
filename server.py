import socketserver
from util.request import Request
from util.router import Router
from util.hello_path import hello_path

from util.response import Response
import json
from util.database import cHATDATA, uSERDATA, rEGISTERDATA, vIDEODATA, dRAWINGDATA, dIRECTMESSAGEDATA, vIDEOCALLDATA

from util.auth import extract_credentials, validate_password
import bcrypt
import hashlib
import uuid

import pyotp
from dotenv import load_dotenv
import os
load_dotenv()
REDIRECTURI = "http://localhost:8080/authcallback"
GITHUBCLIENTID = os.environ["GITHUB_CLIENT_ID"]
GITHUBCLIENTSECRET = os.environ["GITHUB_CLIENT_SECRET"]
import requests

from util.multipart import parse_multipart
import datetime
import subprocess

from util.websockets import compute_accept, parse_ws_frame, generate_ws_frame, parse_ws_frames

import time
import socket
import datetime
from datetime import timezone
import jwt

VIDEO_CALL_ROOMS = {}
SOCKET_TO_CALL = {}
SOCKET_IDS = {}
SOCKET_USERNAMES = {}

with open ("jwtRS256.key.pem", "r") as fp:
    pUBLICKEY = fp.read()

def gETJWTUSER(request, handler):
    '''Get the aUTTHENTICATIONTOKEN'''
    encoded = request.cookies.get("auth_token")

    if not encoded:

        return None

    try:
        '''Decode the payload like in the documentation'''
        payload = jwt.decode(encoded, pUBLICKEY, algorithms=["RS256"])

        payloadDATA = {"id": payload.get("id"), "username": payload.get("username")}

        return payloadDATA

    except jwt.ExpiredSignatureError:

        return None

    except jwt.InvalidTokenError:

        return None


def fINDPUBLIC(request, handler):
    restOFthePATH = ""

    '''Get the file path'''
    if request.path.startswith("/public"):
        restOFthePATH = request.path[len("/public"):]

    '''The path wasnt there'''
    if (restOFthePATH =="") or (restOFthePATH == "/"):
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not Found")

        handler.request.sendall(rESPONCE.to_data())

        return

    pUBLICPATH = "public" + restOFthePATH

    '''Match the 7 MIME types'''
    cONTENTYPE = "text/plain; charset=utf-8"

    if pUBLICPATH.endswith(".jpg") or pUBLICPATH.endswith(".jpeg"):
        cONTENTYPE = "image/jpeg"

    if pUBLICPATH.endswith(".ico"):
        cONTENTYPE = "image/x-icon"

    if pUBLICPATH.endswith(".gif"):
        cONTENTYPE = "image/gif"

    if pUBLICPATH.endswith(".webp"):
        cONTENTYPE = "image/webp"

    if pUBLICPATH.endswith(".js"):
        cONTENTYPE = "text/javascript; charset=utf-8"

    if pUBLICPATH.endswith(".html"):
        cONTENTYPE = "text/html; charset=utf-8"

    if pUBLICPATH.endswith(".png"):
        cONTENTYPE = "image/png"

    if pUBLICPATH.endswith(".mp4"):
        cONTENTYPE = "video/mp4"

    if pUBLICPATH.endswith(".m3u8"):
        cONTENTYPE = "application/vnd.apple.mpegurl"

    if pUBLICPATH.endswith(".ts"):
        cONTENTYPE = "video/mp2t"

    if pUBLICPATH.endswith(".css"):
        cONTENTYPE = "text/css"


    '''No data in gitkeep'''
    if pUBLICPATH.endswith(".gitkeep"):
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not Found")

        handler.request.sendall(rESPONCE.to_data())

        return


    '''Use try and except like we used try and catch in 116'''
    try:

        '''Use with open like in 115 but use rb for readbyte'''
        with open(pUBLICPATH, "rb") as fP:

            '''Read the bytes and store them in fILEBYTES'''
            fILEBYTES = fP.read()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": cONTENTYPE})
        rESPONCE.bytes(fILEBYTES)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not Found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOHOME(request, handler):
    try:

        '''Read the template and index'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with open("public/index.html", "r") as fP:
            iNDEXHTML = fP.read()

        '''Replace the content with the chat and encode for the emojis'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", iNDEXHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOCHAT(request, handler):
    try:

        '''Read the template and chat'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with open("public/chat.html", "r") as fP:
            cHATHTML = fP.read()

        '''Replace the content with the chat and encode for the emojis'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", cHATHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)

    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not found")

    handler.request.sendall(rESPONCE.to_data())


def eXCAPEHTML(HTML):
    eXCAPE = ""

    '''Make & < > into amp lt gt if the character is currently that'''
    for h in HTML:

        if h == "&":
            eXCAPE = eXCAPE + "&amp;"

        elif h == "<":
            eXCAPE = eXCAPE + "&lt;"

        elif h == ">":
            eXCAPE = eXCAPE + "&gt;"

        else:
            eXCAPE = eXCAPE + h

    return eXCAPE



def pOSTCHAT(request, handler):
    try:

        '''Body bytes to json string to dictionary'''
        bODYDICTIONARY = json.loads(request.body.decode())

        '''Get the content'''
        cONTENT = bODYDICTIONARY.get("content", "")

    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())

        return


    sESSIONID = None
    aUTHOR = None
    nEEDSCOOKIE = False

    '''Set the iMAGEURL to something as a placeholder'''
    iMAGEURL = "/public/imgs/user.webp"


    if rEGISTEREDUSER:

        if rEGISTEREDUSER.get("imageURL"):
            '''If the user has uploaded an avatar use it'''
            iMAGEURL = rEGISTEREDUSER.get("imageURL")

        '''Make sure the user exists and the user has a username, then set the aUTHOR to that username'''
        if rEGISTEREDUSER.get("username"):

            aUTHOR = rEGISTEREDUSER["username"]

    '''aUTHOR is not logged in'''
    if aUTHOR == None:

        '''Get the session cookie if it exists'''
        sESSION = request.cookies.get("session")

        if sESSION:

            uSER = uSERDATA.find_one({"session": sESSION})

            if uSER:

                sESSIONID = uSER["session"]
                aUTHOR = uSER["author"]


        '''aUTHOR is not logged in and has no session cookie'''
        if (aUTHOR == None) and (sESSION == None):

            '''Make a sessionid for this user'''
            sESSIONID = uuid.uuid4().hex
            '''Make a author for this user'''
            aUTHOR = "User" + sESSIONID

            '''Add the user to the database'''
            uSERDATA.insert_one({"session": sESSIONID, "author": aUTHOR})

            nEEDSCOOKIE = True

    '''Make a chatid for this chat'''
    cHATID = uuid.uuid4().hex

    '''Insert the chat to the chat database'''
    cHATDATA.insert_one({"id": cHATID, "author": aUTHOR, "content": cONTENT, "updated": False, "imageURL": iMAGEURL})

    '''Make a new responce'''
    rESPONCE = Response()
    rESPONCE.text("message sent")

    '''If the user is new add cookie and set the path to /'''
    if nEEDSCOOKIE:
        sETCOOKIE = "session=" + sESSIONID + "; Path=/"
        rESPONCE.headers({"Set-Cookie": sETCOOKIE})


    handler.request.sendall(rESPONCE.to_data())


def gETCHAT(request, handler):
    '''Store the messages'''
    mESSAGES = []

    '''Add each chat to mESSAGES'''
    for cHAT in cHATDATA.find({}):
        mESSAGES.append({

            "author": cHAT.get("author"),
            "id": cHAT.get("id"),
            "content": eXCAPEHTML(str(cHAT.get("content", ""))),
            "updated": cHAT.get("updated", False),
            "imageURL": cHAT.get("imageURL")
        })

    rESPONCE = Response()
    rESPONCE.json({"messages": mESSAGES})

    handler.request.sendall(rESPONCE.to_data())


def pATCHCHAT(request, handler):
    '''Get the chatid'''
    sTARTSWITH = "/api/chats/"
    cHATID = request.path[len(sTARTSWITH):]

    '''Get the chat information'''
    cHATINFORMATION = cHATDATA.find_one({"id": cHATID})

    '''The chat information was not found'''
    if not cHATINFORMATION:
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    '''If it is None or the author isnt the same'''
    if (not rEGISTEREDUSER) or (rEGISTEREDUSER.get("username") != cHATINFORMATION.get("author")):
        rESPONCE = Response()
        rESPONCE.set_status(403, "Forbidden")
        rESPONCE.text("no permission")

        handler.request.sendall(rESPONCE.to_data())
        return

    try:

        '''Get the new body'''
        bODY = json.loads((request.body).decode())


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("Not found")

        handler.request.sendall(rESPONCE.to_data())
        return

    '''Store the new content from the new body'''
    nEWCONTENT = bODY.get("content")

    '''Update the content'''
    cHATDATA.update_one({"id": cHATID}, {"$set": {"content": nEWCONTENT, "updated": True}})

    rESPONCE = Response()
    rESPONCE.text("message updated")

    handler.request.sendall(rESPONCE.to_data())


def dELETECHAT(request, handler):
    '''Get the chatid'''
    sTARTSWITH = "/api/chats/"
    cHATID = request.path[len(sTARTSWITH):]

    '''Get the chat information'''
    cHATINFORMATION = cHATDATA.find_one({"id": cHATID})

    '''The chat information was not found'''
    if not cHATINFORMATION:
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("message not found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    '''If it is None or the author isnt the same'''
    if (not rEGISTEREDUSER) or (rEGISTEREDUSER.get("username") != cHATINFORMATION.get("author")):
        rESPONCE = Response()
        rESPONCE.set_status(403, "Forbidden")
        rESPONCE.text("no permission")

        handler.request.sendall(rESPONCE.to_data())
        return

    '''Delete the chat'''
    cHATDATA.delete_one({"id": cHATID})

    rESPONCE = Response()
    rESPONCE.text("message deleted")

    handler.request.sendall(rESPONCE.to_data())





def mOVETOSETTINGS(request, handler):
    try:

        '''Read the template and settings'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/settings.html", "r")) as fP:
            sETTINGSHTML = fP.read()

        '''Replace the content with the settings content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", sETTINGSHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOSEARCHUSERS(request, handler):
    try:

        '''Read the template and search users'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/search-users.html", "r")) as fP:
            sEARCHUSERSHTML = fP.read()

        '''Replace the content with the search users content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", sEARCHUSERSHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())


def gETME(request, handler):

    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())

        return

    '''Return the username and id'''
    rESPONCE = Response()
    rESPONCE.json({"username": rEGISTEREDUSER["username"], "id": rEGISTEREDUSER.get("id"), "imageURL": rEGISTEREDUSER.get("imageURL")})

    handler.request.sendall(rESPONCE.to_data())


def gETSEARCHUSERS(request, handler):

    '''The uSERVALUE we found'''
    uSERVALUE = ""

    if "?" in request.path:

        pARTS = request.path.split("?", 1)

        qUERY = pARTS[1]

        for pART in qUERY.split("&"):

            if pART.startswith("user="):
                pARTVALUE = pART.split("=", 1)[1]

                pARTVALUE = pARTVALUE.replace("+", " ")

                sTORAGE = ""

                x = 0

                while x < len(pARTVALUE):

                    if (pARTVALUE[x] == "%") and ((x + 2) < len(pARTVALUE)):

                        '''Get the two values after the %'''
                        hEX1 = pARTVALUE[x + 1]
                        hEX2 = pARTVALUE[x + 2]

                        '''Make sure that the characters are right'''
                        iSHEX1 = False
                        iSHEX2 = False
                        if (("0" <= hEX1 <= "9") or ("a" <= hEX1 <= "f") or ("A" <= hEX1 <= "F")):
                            iSHEX1 = True

                        if (("0" <= hEX2 <= "9") or ("a" <= hEX2 <= "f") or ("A" <= hEX2 <= "F")):
                            iSHEX2 = True

                        if iSHEX1 == True and iSHEX2 == True:
                            '''Turn the hex string into a number'''
                            nUMBEROFVALUE = int((hEX1 + hEX2), 16)

                            '''Turn the number into a character'''
                            cHARACTEROFVALUE = chr(nUMBEROFVALUE)

                            '''Store the character'''
                            sTORAGE = sTORAGE + cHARACTEROFVALUE

                            '''Move from the hex'''
                            x = x + 3

                        else:

                            sTORAGE = sTORAGE + pARTVALUE[x]
                            x = x + 1

                    else:

                        sTORAGE = sTORAGE + pARTVALUE[x]
                        x = x + 1

                uSERVALUE = sTORAGE
                break

    if uSERVALUE == "":
        rESPONCE = Response()
        rESPONCE.json({"users": []})

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get all of the registered users'''
    rEGISTEREDUSERS = rEGISTERDATA.find({})

    '''Make a list of the user information from the users matched'''
    uSERINFORMATIONLIST = []

    for uSER in rEGISTEREDUSERS:

        '''Find the users that match with the user value from the registered database'''
        userNAME = uSER.get("username", "")

        if uSERVALUE in userNAME:

            uSERINFORMATIONLIST.append({"id": uSER.get("id"), "username": uSER.get("username")})


    rESPONCE = Response()
    rESPONCE.json({"users": uSERINFORMATIONLIST})

    handler.request.sendall(rESPONCE.to_data())


def pOSTUPDATEPROFILESETTINGS(request, handler):
    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the users new username and new password'''
    [nEWUSERNAME, nEWPASSWORD, tOTP] = extract_credentials(request)

    nEWUSERNAMEpassword = {}

    '''If the user is updating their password we make sure the new password is valid'''
    if nEWPASSWORD:

        '''The new password that the user inputed is invalid'''
        if not validate_password(nEWPASSWORD):
            rESPONCE = Response()
            rESPONCE.set_status(400, "Bad Request")
            rESPONCE.text("password is invalid")

            handler.request.sendall(rESPONCE.to_data())

            return

        '''Turn the password string into bytes'''
        nEWPASSWORDBYTES = nEWPASSWORD.encode()

        '''Make a bcrypt salt'''
        nEWBCRYPTSALT = bcrypt.gensalt()

        '''Hash and salt the password'''
        nEWHASHEDPASSWORD = bcrypt.hashpw(nEWPASSWORDBYTES, nEWBCRYPTSALT)

        '''Turn the hashed bytes into a string'''
        nEWHASHEDpasswordSTRING = nEWHASHEDPASSWORD.decode()

        '''Store the new hashed password string'''
        nEWUSERNAMEpassword["password"] = nEWHASHEDpasswordSTRING



    '''If the user is updating their username'''
    if nEWUSERNAME:

        nEWUSERNAMEpassword["username"] = nEWUSERNAME



    '''Update the registered user database to have the new username and new password'''
    rEGISTERDATA.update_one({"id": rEGISTEREDUSER.get("id")}, {"$set": nEWUSERNAMEpassword})


    rESPONCE = Response()
    rESPONCE.text("profile updated")

    handler.request.sendall(rESPONCE.to_data())



def pOSTGENERATE2FA(request, handler):
    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())

        return

    '''Use the pyotp to make a secret'''
    sECRET = pyotp.random_base32()

    '''Put the secret in the registered database'''
    rEGISTERDATA.update_one({"id": rEGISTEREDUSER["id"]}, {"$set": {"twoFactorSecret": sECRET}})

    '''Send the json string as a response'''
    rESPONCE = Response()
    rESPONCE.json({"secret": sECRET})

    handler.request.sendall(rESPONCE.to_data())


def pOSTAVATARUPLOAD(request, handler):
    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())

        return

    '''Use parse multipart on the request'''
    mULTIPART = parse_multipart(request)

    '''Get the avatar part'''
    aVATARPART = ""
    for pART in mULTIPART.parts:
        if pART.name == "avatar":
            aVATARPART = pART

    '''Avatar part is not found'''
    if aVATARPART == "":
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("no avatar found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the content type'''
    cONTENTTYPE = ""
    if "Content-Type" in aVATARPART.headers:

        cONTENTTYPE = aVATARPART.headers["Content-Type"]

    '''Get the mime type. If the mime type isnt png, jpg, or gif it is wrong'''
    MIMETYPE = ""

    if cONTENTTYPE == "image/png":
        MIMETYPE = "png"

    elif cONTENTTYPE == "image/jpg" or cONTENTTYPE == "image/jpeg":
        MIMETYPE = "jpeg"

    elif cONTENTTYPE == "image/gif":
        MIMETYPE = "gif"

    else:

        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("not png, jpg, or gif")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the user id'''
    uSERID = rEGISTEREDUSER["id"]

    '''Use the user id and mime tyoe to make a path for the avatar'''
    uSERIDandMIMETYPE = uSERID + "." + MIMETYPE


    aVATARBYTESPATH = "public/imgs/avatars/" + uSERIDandMIMETYPE

    '''Write the file bytes in the file '''
    try:
        with open(aVATARBYTESPATH, "wb") as fP:

            fP.write(aVATARPART.content)

    except:

        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("image bytes not saved")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Update the users information to have their avatar'''
    rEGISTERDATA.update_one({"id": uSERID}, {"$set": {"imageURL": aVATARBYTESPATH}})

    rESPONCE = Response()
    rESPONCE.set_status(200, "OK")
    rESPONCE.text(aVATARBYTESPATH)

    handler.request.sendall(rESPONCE.to_data())

def mOVETOCHANGEAVATAR(request, handler):
    try:

        '''Read the template and change avatar'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/change-avatar.html", "r")) as fP:
            cHANGEAVATARHTML = fP.read()

        '''Replace the content with the change avatar content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", cHANGEAVATARHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOVIDEOTUBE(request, handler):
    try:

        '''Read the template and videotube'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/videotube.html", "r")) as fP:
            vIDEOTUBEHTML = fP.read()

        '''Replace the content with the videotube content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", vIDEOTUBEHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOVIDEOTUBEUPLOAD(request, handler):
    try:

        '''Read the template and videotube upload'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/upload.html", "r")) as fP:
            uPLOADHTML = fP.read()

        '''Replace the content with the videotube upload content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", uPLOADHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOVIDEO(request, handler):
    try:

        '''Read the template and view video'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/view-video.html", "r")) as fP:
            vIEWVIDEOHTML = fP.read()

        '''Replace the content with the view video content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", vIEWVIDEOHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def pOSTUPLOADVIDEOS(request, handler):
    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())

        return

    '''Use parse multipart on the request'''
    mULTIPART = parse_multipart(request)

    '''Get the video title and discription and the video PART'''
    tITLE = ""
    dESCRIPTION = ""
    vIDEOPART = None

    for pART in mULTIPART.parts:
        '''If the title is found turn the bytes into a string and store it in tITLE'''
        if pART.name == "title":
            tITLE = pART.content.decode()

        elif pART.name == "description":
            '''If the discription is found turn the bytes into a string and store it in dISCRIPTION'''
            dESCRIPTION = pART.content.decode()

        elif pART.name == "video":
            '''Store the part in vIDEOPART'''
            vIDEOPART = pART

    '''The video part was not found'''
    if vIDEOPART == None:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("no video part")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the content type'''
    cONTENTTYPE = vIDEOPART.headers.get("Content-Type", "").lower()

    '''The content type should be mp4'''
    if "video/mp4" not in cONTENTTYPE :
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("content type is not mp4")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Create a video id'''
    vIDEOID = uuid.uuid4().hex

    '''Make the path for the video'''
    vIDEOBYTESPATH = "public/videos/" + vIDEOID + ".mp4"

    '''Write the file bytes in the file '''
    try:
        with open(vIDEOBYTESPATH, "wb") as fP:
            fP.write(vIDEOPART.content)

    except:

        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("video not saved")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Make the current date and time and turn it into a string'''
    mAKEDATETIME = datetime.datetime.now()
    mAKEDATETIMESTRING = mAKEDATETIME.strftime("%m/%d/%Y %H:%M:%S")

    '''Get the videos total run time'''
    cOMPLETETIME = 0.0

    try:

        '''Use ffprobe, -print_format then json tells ffprobe to give the result in json, -show_format is to show the format section information, vIDEOBYTESPATH is the path to the video, 
        capture_output=True stores in cOMPLETEDPROCESS instead of printing to terminal'''
        cOMPLETEDPROCESS = subprocess.run(["ffprobe", "-print_format", "json", "-show_format", vIDEOBYTESPATH], capture_output=True)

        '''Use json to load format like in recitation'''
        fORMAT = json.loads(cOMPLETEDPROCESS.stdout)

        '''Store the duration in cOMPLETETIME in as a float using the way in recitation'''
        cOMPLETETIME = float(fORMAT["format"]["duration"])

    except Exception:

        cOMPLETETIME = 0.0

    '''Make 5 timestamps for the 5 thumbnails, first frame, 25%, 50%, 75%, last frame - 0.1 so it works'''
    tIME0 = 0.0
    tIME1 = cOMPLETETIME * 0.25
    tIME2 = cOMPLETETIME * 0.50
    tIME3 = cOMPLETETIME * 0.75
    tIME4 = cOMPLETETIME - 0.1

    '''Store the 5 timestamps'''
    tIMESTAMPS = [tIME0, tIME1, tIME2, tIME3, tIME4]

    '''Store the paths of the 5 possible thumbnails'''
    tHUMBNAILPOSSIBLEITIES = []

    x = 0

    while x < 5:

        '''Make the paths for the thumbnail'''
        tHUMBNAILOUTPUTPATH = "public/imgs/thumbnails/" + vIDEOID + "_" + str(x) + ".jpg"


        try:
            '''Uses ffmpeg, -i tells in input path is vIDEOBYTESPATH, -ss tells the timestamp is tIMESTAMPS[x], -frames:v 1 tells to take one video frame, output file is tHUMBNAILOUTPUTPATH'''
            subprocess.run(["ffmpeg", "-i", vIDEOBYTESPATH, "-ss", str(tIMESTAMPS[x]), "-frames:v", "1", tHUMBNAILOUTPUTPATH])

            tHUMBNAILPOSSIBLEITIES.append(tHUMBNAILOUTPUTPATH)

        except Exception:
            pass

        x = x + 1

    '''Make the first thumbnail the default thumbnail'''
    tHECHOSEN = ""
    if len(tHUMBNAILPOSSIBLEITIES) > 0:
        tHECHOSEN = tHUMBNAILPOSSIBLEITIES[0]


    '''Make a directory for each hls video'''
    hLSDIRECTORY = "public/videos/hls/" + vIDEOID + "/"

    os.makedirs(hLSDIRECTORY, exist_ok=True)

    mAINHLSPATH = ""

    try:
        '''
        Uses ffmpeg, -i tells in input path is vIDEOBYTESPATH,
        -filter_complex tells to run many video filters at once
        [0:v]split=2[1080pINPUT][480pINPUT] takes the input video stream and turns it into two copys named 1080pINPUT and 480pINPUT
        [1080pINPUT]scale=w=1920:h=1080[1080pOUTPUT] tells to make the 1080pINPUT video copy 1920 width and 1080 height
        [480pINPUT]scale=w=854:h=480[480pOUTPUT] tells to make the 480pINPUT video copy 854 width and 480 height
        "-map", "[1080pOUTPUT]" tells to use the [1080pOUTPUT]
        "-map", "0:a" tells to use the audio form the vIDEOBYTESPATH video
        "-c:v:0", "libx264" tells to encode the 1080pOUTPUT video with libx264
        "-b:v:0", "4700k" tells to set the bitrate to 4700k
        "-c:a:0", "aac" tells to encode the first video's audio with aac
        "-b:a:0", "170k" tells to set the audio bitrate to 170k
        "-map", "[480pOUTPUT]" tells to use the [480pOUTPUT]
        "-map", "0:a" tells to use the audio form the vIDEOBYTESPATH video
        "-c:v:1", "libx264" tells to encode the 480pOUTPUT video with libx264
        "-b:v:1", "900k" tells to set the bitrate to 900k
        "-c:a:1", "aac" tells to encode the second video's audio with aac
        "-b:a:1", "110k" tells to set the audio bitrate to 110k
        "-f", "hls" tells to use the hls output format
        "-hls_time", "5" splits the video into segments of 5 seconds
        "-hls_list_size", "0" tells to store all of the .ts files that are made
        "-hls_segment_filename", hLSDIRECTORY + "%v_%04d.ts" tells to name each .ts with "%v being 0 or 1 (for 1080p or 480p) and %04d being a four digit number for the segment
        "-var_stream_map", "v:0,a:0 v:1,a:1" tells to combine the 1080p video with its audio and combine the 480p video with its audio
        "-master_pl_name", "master.m3u8" tells to name the master file master.m3u8 where the .m3u8 files for the 1080p video and 480p video are stored
        hLSDIRECTORY + "%v.m3u8" tells the output path for the 1080p video .m3u8 and the 480p video .m3u8 with "%v being 0 or 1 (for 1080p or 480p)
        '''
        subprocess.run(["ffmpeg", "-i", vIDEOBYTESPATH,
                        "-filter_complex", "[0:v]split=2[1080pINPUT][480pINPUT];[1080pINPUT]scale=w=1920:h=1080[1080pOUTPUT];[480pINPUT]scale=w=854:h=480[480pOUTPUT]",
                        "-map", "[1080pOUTPUT]",
                        "-map", "0:a", "-c:v:0", "libx264", "-b:v:0", "4700k",
                        "-c:a:0", "aac", "-b:a:0", "170k",
                        "-map", "[480pOUTPUT]",
                        "-map", "0:a", "-c:v:1", "libx264", "-b:v:1", "900k",
                        "-c:a:1", "aac", "-b:a:1", "110k",
                        "-f", "hls",
                        "-hls_time", "5",
                        "-hls_list_size", "0",
                        "-hls_segment_filename", hLSDIRECTORY + "%v_%04d.ts",
                        "-var_stream_map", "v:0,a:0 v:1,a:1",
                        "-master_pl_name", "master.m3u8",
                        hLSDIRECTORY + "%v.m3u8"])


        mAINHLSPATH = hLSDIRECTORY + "master.m3u8"


    except Exception:
        mAINHLSPATH = ""


    '''Insert the video data'''
    vIDEODATA.insert_one({"author_id": rEGISTEREDUSER["id"], "title": tITLE, "description": dESCRIPTION, "video_path": vIDEOBYTESPATH,
                          "created_at": mAKEDATETIMESTRING, "id": vIDEOID, "thumbnails": tHUMBNAILPOSSIBLEITIES, "thumbnailURL": tHECHOSEN, "hls_path": "/" + mAINHLSPATH})


    rESPONCE = Response()
    rESPONCE.set_status(200, "OK")
    rESPONCE.json({"id": vIDEOID})

    handler.request.sendall(rESPONCE.to_data())

def gETVIDEOS(request, handler):

    '''Add all of the videos from the database'''
    vIDEOS = []

    '''Append each video data from the database to vIDEOS'''
    for vIDEO in vIDEODATA.find({}):
        vIDEOS.append({"author_id": vIDEO.get("author_id"), "title": vIDEO.get("title"), "description": vIDEO.get("description"), "video_path": vIDEO.get("video_path"), "created_at": vIDEO.get("created_at"),
                       "id": vIDEO.get("id"), "thumbnails": vIDEO.get("thumbnails"), "thumbnailURL": vIDEO.get("thumbnailURL"), "hls_path": vIDEO.get("hls_path")})

    '''Make the most recently added video first'''
    vIDEOS.reverse()

    '''Send the video data'''
    rESPONCE = Response()
    rESPONCE.set_status(200, "OK")
    rESPONCE.json({"videos": vIDEOS})

    handler.request.sendall(rESPONCE.to_data())

def gETVIDEOSVIDEOID(request, handler):

    '''Get the video id'''
    pATHSTART = "/api/videos/"
    vIDEOID = request.path[len(pATHSTART):]

    '''Get the video from the database with the video id'''
    vIDEO = vIDEODATA.find_one({"id": vIDEOID})

    '''The video is not found'''
    if not vIDEO:
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("video not found")

        handler.request.sendall(rESPONCE.to_data())

        return

    rESPONCE = Response()
    rESPONCE.set_status(200, "OK")

    '''Get the video data'''
    vIDEODICTIONARY = {"author_id": vIDEO.get("author_id"), "title": vIDEO.get("title"), "description": vIDEO.get("description"), "video_path": vIDEO.get("video_path"), "created_at": vIDEO.get("created_at"),
                       "id": vIDEO.get("id"), "thumbnails": vIDEO.get("thumbnails"), "thumbnailURL": vIDEO.get("thumbnailURL"), "hls_path": vIDEO.get("hls_path")}
    rESPONCE.json({"video": vIDEODICTIONARY})

    handler.request.sendall(rESPONCE.to_data())


def mOVETOSETTHUMBNAIL(request, handler):
    try:

        '''Read the template and set thumbnail'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/set-thumbnail.html", "r")) as fP:
            sETTHUMBNAIL = fP.read()

        '''Replace the content with the set thumbnail content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", sETTHUMBNAIL).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def pUTTHUMBNAIL(request, handler):
    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the video id'''
    sTARTSWITH = "/api/thumbnails/"
    vIDEOID = request.path[len(sTARTSWITH):]

    '''Get the video information'''
    vIDEOINFORMATION = vIDEODATA.find_one({"id": vIDEOID})

    '''The video information was not found'''
    if not vIDEOINFORMATION:
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("message not found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''If the videos author id and the users id doesnt match there is a problem'''
    if vIDEOINFORMATION.get("author_id") != rEGISTEREDUSER.get("id"):
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.json({})

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Store the chosen thumbnail'''
    tHECHOSEN = ""

    '''Use try and expect because we are tickling json'''
    try:

        '''Get the new thumbnail'''
        bODY = json.loads((request.body).decode())
        tHECHOSEN = bODY.get("thumbnailURL")

    except Exception:

        rESPONCE = Response()

        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("json went wrong")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Make sure the chosen thumbnail exists'''
    if tHECHOSEN == "":
        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("the chosen thumbnail is not found")

        handler.request.sendall(rESPONCE.to_data())

        return


    '''Update the video data'''
    vIDEODATA.update_one({"id": vIDEOID}, {"$set": {"thumbnailURL": tHECHOSEN}})


    rESPONCE = Response()
    rESPONCE.set_status(200, "OK")
    rESPONCE.json({"message": "thumbnail update was successful"})

    handler.request.sendall(rESPONCE.to_data())


def mOVETOTESTWEBSOCKET(request, handler):
    try:

        '''Read the template and test websocket'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/test-websocket.html", "r")) as fP:
            tESTWEBSOCKET = fP.read()

        '''Replace the content with the test websocket content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", tESTWEBSOCKET).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETODRAWINGBOARD(request, handler):
    try:

        '''Read the template and drawing board'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/drawing-board.html", "r")) as fP:
            dRAWINGBOARD = fP.read()

        '''Replace the content with the drawing board content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", dRAWINGBOARD).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETODIRECTMESSAGING(request, handler):
    try:

        '''Read the template and direct messaging'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/direct-messaging.html", "r")) as fP:
            dIRECTmessagingHTML = fP.read()

        '''Replace the content with the direct messaging content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", dIRECTmessagingHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())


def mOVETOVIDEOCALL(request, handler):
    try:

        '''Read the template and drawing board'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/video-call.html", "r")) as fP:
            dRAWINGBOARD = fP.read()

        '''Replace the content with the drawing board content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", dRAWINGBOARD).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOVIDEOCALLROOM(request, handler):
    try:

        '''Read the template and drawing board'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/video-call-room.html", "r")) as fP:
            dRAWINGBOARD = fP.read()

        '''Replace the content with the drawing board content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", dRAWINGBOARD).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())

def mOVETOVIEWVIDEO(request, handler):
    try:

        '''Read the template and view video'''
        with open("public/layout/layout.html", "r") as fP:
            lAYOUTHTML = fP.read()
        with (open("public/view-video.html", "r")) as fP:
            vIEWVIDEOHTML = fP.read()

        '''Replace the content with the view video content'''
        uSETEMPLATE = lAYOUTHTML.replace("{{content}}", vIEWVIDEOHTML).encode()

        rESPONCE = Response()
        rESPONCE.headers({"Content-Type": "text/html; charset=utf-8"})
        rESPONCE.bytes(uSETEMPLATE)


    except Exception:

        rESPONCE = Response()
        rESPONCE.set_status(404, "Not Found")
        rESPONCE.text("not found")

    handler.request.sendall(rESPONCE.to_data())



def gETWEBSOCKET(request, handler):
    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    uSERNAME = "Guest"

    if rEGISTEREDUSER:

        uSERNAME = (rEGISTEREDUSER.get("username") or "Guest")

    '''Get the connection and upgrade headers'''
    cONNECTIONHEADER = (request.headers.get("Connection") or "").strip()
    uPGRADEHEADER = (request.headers.get("Upgrade") or "").strip()

    '''The value of the connection header should be upgrade'''
    if "upgrade" not in cONNECTIONHEADER.lower():
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("connection header is not upgrade")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''The value of the upgrade header should be websocket'''
    if "websocket" not in uPGRADEHEADER.lower():

        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("upgrade header is not websocket")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get the sec websocket key'''
    sECwebsocketKEY = (request.headers.get("Sec-WebSocket-Key") or "")

    '''No sec websocket key'''
    if not sECwebsocketKEY:

        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("sec websocket key not found")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Get te key and do websocket handshake'''
    sECwebsocketACCEPT = compute_accept(sECwebsocketKEY)

    handler.request.sendall(

        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + sECwebsocketACCEPT.encode() + b"\r\n"
        b"\r\n"

    )

    '''Store the socket id and username for video calls'''
    if handler.request not in SOCKET_IDS:
        SOCKET_IDS[handler.request] = uuid.uuid4().hex
    SOCKET_USERNAMES[handler.request] = uSERNAME

    '''Store all of the drawing history'''
    dRAWINGHISTORY = []

    '''Go though each drawing in the drawing data'''
    for dRAWING in dRAWINGDATA.find({}):

        oNEDRAWING = {}
        for kEY, vALUE in dRAWING.items():
            '''Add the drawing to one drawing but dont add the _id'''
            if kEY != "_id":
                oNEDRAWING[kEY] = vALUE
        dRAWINGHISTORY.append(oNEDRAWING)

    try:
        '''Turn dRAWINGHISTORY into a json string and store as payload with the messageType'''
        pAYLOAD = json.dumps({"messageType": "init_strokes", "strokes": dRAWINGHISTORY}).encode()
        '''Make a websocket frame'''
        oUTGOINGFRAME = generate_ws_frame(pAYLOAD)
        '''Send the websocket frame to the user'''
        handler.request.sendall(oUTGOINGFRAME)

    except Exception:
        pass

    '''Store the client users TCPHandler and username in aCTIVECLIENTLIST to make it easier to broadcast all of the all websocket connections'''
    MyTCPHandler.aCTIVECLIENTLIST.append({"socket": handler.request, "username": uSERNAME})

    '''Store a list of the connected active users'''
    aCTIVEUSERSLIST = []

    '''Go through each of the clients in the active client list'''
    for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:

        '''Store each username in aCTIVEUSERSLIST'''
        if cLIENT["username"]:
            aCTIVEUSERSLIST.append({"username": cLIENT["username"]})

    '''Turn the list of aCTIVEUSERSLIST into a json string and store as payload with the messageType'''
    bROADCASTPAYLOAD = json.dumps({"messageType": "active_users_list", "users": aCTIVEUSERSLIST}).encode()
    '''Make a websocket frame'''

    bROADCASTWEBFRAME = generate_ws_frame(bROADCASTPAYLOAD)

    '''Go through each of the clients in the active client list and send the websocket frame to the client'''
    for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:

        try:
            cLIENT["socket"].sendall(bROADCASTWEBFRAME)

        except Exception:
            pass

    '''Store the bytes from the buffer'''
    bUFFERBYTES = b""
    cONNECTIONCLOSED = False

    cURRENTOPCODE = None
    cURRENTMESSAGEBYTES = b""

    while cONNECTIONCLOSED == False:

        '''Read 4096 bytes at a time and store the bytes in bUFFERBYTES'''
        try:
            cHUNK = handler.request.recv(4096)
        except Exception:
            cHUNK = b""

        if not cHUNK:
            cONNECTIONCLOSED = True
            break

        bUFFERBYTES = bUFFERBYTES + cHUNK

        '''Parse all frames we can and leave the remaining bytes in bUFFERBYTES'''
        fRAMES, rEMAINING = parse_ws_frames(bUFFERBYTES)
        bUFFERBYTES = rEMAINING

        '''Go through each parsed frame'''
        for fRAME in fRAMES:

            '''If the client sends a close frame with opcode 1000 then break'''
            if fRAME.opcode == 8:
                cONNECTIONCLOSED = True
                break

            '''If the client sends a close frame with opcode 0001 then decode'''
            fULLMESSAGE = None
            fULLOPCODE = None

            '''Text frame (opcode 1) starts a message'''
            if fRAME.opcode == 1:

                '''If fin bit is 1 then the message is done'''
                if fRAME.fin_bit == 1:
                    fULLMESSAGE = fRAME.payload
                    fULLOPCODE = 1

                else:
                    '''If fin bit is 0 then we buffer'''
                    cURRENTOPCODE = 1
                    cURRENTMESSAGEBYTES = fRAME.payload
                    continue

            elif fRAME.opcode == 0:

                '''If we are not buffering anything ignore'''
                if cURRENTOPCODE == None:
                    continue

                '''Add the continuation bytes'''
                cURRENTMESSAGEBYTES = cURRENTMESSAGEBYTES + fRAME.payload

                '''If fin bit is 1 then the message is done'''
                if fRAME.fin_bit == 1:
                    fULLMESSAGE = cURRENTMESSAGEBYTES
                    fULLOPCODE = cURRENTOPCODE

                    '''Reset buffering'''
                    cURRENTOPCODE = None
                    cURRENTMESSAGEBYTES = b""

                else:
                    continue

            else:
                '''Ignore other opcodes like ping/pong'''
                continue

            '''Only handle json for text messages'''
            if fULLOPCODE != 1:
                continue

            '''Decode and load json'''
            try:
                jSONTEXT = fULLMESSAGE.decode()
                mESSAGE = json.loads(jSONTEXT)
            except Exception:
                mESSAGE = None

            '''If message is not none'''
            if mESSAGE != None:
                '''Get the message type'''
                mESSAGETYPE = mESSAGE.get("messageType")

                if mESSAGETYPE == "echo_client":

                    '''Turn message into a json string and store as payload with the messageType'''
                    eCHOSERVERPAYLOAD = json.dumps(
                        {"messageType": "echo_server", "text": mESSAGE.get("text", "")}
                    ).encode()

                    '''Make a websocket frame'''
                    eCHOserverWEBSOCKETframe = generate_ws_frame(eCHOSERVERPAYLOAD)

                    '''Send the websocket frame to the user'''
                    try:
                        handler.request.sendall(eCHOserverWEBSOCKETframe)
                    except Exception:
                        pass

                elif mESSAGETYPE == "drawing":
                    '''Store the new drawing data in the database'''
                    nEWDRAWING = {
                        "startX": mESSAGE.get("startX"),
                        "startY": mESSAGE.get("startY"),
                        "endX": mESSAGE.get("endX"),
                        "endY": mESSAGE.get("endY"),
                        "color": mESSAGE.get("color")
                    }
                    dRAWINGDATA.insert_one(nEWDRAWING)

                    '''Turn message into a json string and store as payload with the messageType'''
                    nEWDRAWINGPAYLOAD = json.dumps(mESSAGE).encode()

                    '''Make a websocket frame'''
                    nEWdrawingWEBSOCKETframe = generate_ws_frame(nEWDRAWINGPAYLOAD)

                    try:
                        handler.request.sendall(nEWdrawingWEBSOCKETframe)
                    except Exception:
                        pass

                    '''Go through each of the clients in the active client list and send the websocket frame to the client'''
                    for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:
                        if cLIENT["socket"] == handler.request:
                            continue
                        try:
                            cLIENT["socket"].sendall(nEWdrawingWEBSOCKETframe)
                        except Exception:
                            pass

                elif mESSAGETYPE == "active_users_list":
                    '''Store a list of the connected active users'''
                    aCTIVEUSERSLIST = []

                    '''Go through each of the clients in the active client list'''
                    for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:

                        '''Store each username in aCTIVEUSERSLIST'''
                        if cLIENT["username"]:
                            aCTIVEUSERSLIST.append({"username": cLIENT["username"]})

                    '''Turn the list of aCTIVEUSERSLIST into a json string and store as payload with the messageType'''
                    bROADCASTPAYLOAD = json.dumps({"messageType": "active_users_list", "users": aCTIVEUSERSLIST}).encode()

                    '''Make a websocket frame'''
                    bROADCASTWEBFRAME = generate_ws_frame(bROADCASTPAYLOAD)

                    '''Go through each of the clients in the active client list and send the websocket frame to the client'''
                    for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:
                        try:
                            cLIENT["socket"].sendall(bROADCASTWEBFRAME)
                        except Exception:
                            pass


                elif mESSAGETYPE == "get_calls":

                    cALLS = []

                    for cALL in vIDEOCALLDATA.find({}):

                        cALLID = cALL.get("id")

                        cALLNAME = cALL.get("name")

                        if cALLID and cALLNAME:
                            cALLS.append({"id": cALLID, "name": cALLNAME})

                    cALLLISTPAYLOAD = json.dumps({"messageType": "call_list","calls": cALLS}).encode()

                    cALLLISTFRAME = generate_ws_frame(cALLLISTPAYLOAD)

                    try:

                        handler.request.sendall(cALLLISTFRAME)

                    except Exception:

                        pass


                elif mESSAGETYPE == "join_call":
                    '''Get the call id from the message'''
                    cALLID = mESSAGE.get("callId")

                    if not cALLID:
                        continue

                    '''Make sure the room exists in memory'''
                    if cALLID not in VIDEO_CALL_ROOMS:

                        cALLDOC = vIDEOCALLDATA.find_one({"id": cALLID})

                        if not cALLDOC:
                            continue

                        VIDEO_CALL_ROOMS[cALLID] = {"name": (cALLDOC.get("name") or ""), "participants": {}}

                    '''If the user was in a previous call, remove them'''
                    if handler.request in SOCKET_TO_CALL:

                        oLDCALL = SOCKET_TO_CALL.get(handler.request)

                        if oLDCALL in VIDEO_CALL_ROOMS:
                            VIDEO_CALL_ROOMS[oLDCALL]["participants"].pop(handler.request, None)

                    SOCKET_TO_CALL[handler.request] = cALLID

                    rOOM = VIDEO_CALL_ROOMS[cALLID]
                    pARTICIPANTS = rOOM["participants"]

                    '''Send call_info to the joining user'''
                    cALLINFOPAYLOAD = json.dumps({"messageType": "call_info", "name": rOOM.get("name", "")}).encode()
                    cALLINFOFRAME = generate_ws_frame(cALLINFOPAYLOAD)

                    try:
                        handler.request.sendall(cALLINFOFRAME)
                    except Exception:
                        pass

                    '''Send existing_participants to the joining user'''
                    eXISTING = []

                    for sOCK, iNFO in pARTICIPANTS.items():
                        eXISTING.append({"socketId": iNFO.get("socketId"), "username": iNFO.get("username")})

                    eXISTINGPAYLOAD = json.dumps({"messageType": "existing_participants", "participants": eXISTING}).encode()
                    eXISTINGFRAME = generate_ws_frame(eXISTINGPAYLOAD)

                    try:
                        handler.request.sendall(eXISTINGFRAME)
                    except Exception:
                        pass

                    '''Add the joining user to the room'''
                    sOCKETID = SOCKET_IDS.get(handler.request)
                    jOINUSERNAME = SOCKET_USERNAMES.get(handler.request, "Guest")

                    pARTICIPANTS[handler.request] = {"socketId": sOCKETID, "username": jOINUSERNAME}

                    '''Broadcast user_joined to everyone else in the call'''
                    uSERJOINEDPAYLOAD = json.dumps(
                        {"messageType": "user_joined", "socketId": sOCKETID, "username": jOINUSERNAME}
                    ).encode()
                    uSERJOINEDFRAME = generate_ws_frame(uSERJOINEDPAYLOAD)

                    for sOCK in pARTICIPANTS:
                        if sOCK == handler.request:
                            continue
                        try:
                            sOCK.sendall(uSERJOINEDFRAME)
                        except Exception:
                            pass

                elif (mESSAGETYPE == "offer") or (mESSAGETYPE == "answer") or (mESSAGETYPE == "ice_candidate"):

                    '''The receiver socket id'''
                    tARGETSOCKETID = mESSAGE.get("socketId")

                    if not tARGETSOCKETID:
                        continue

                    '''Find what call the sender is in'''
                    cALLID = SOCKET_TO_CALL.get(handler.request)

                    if not cALLID:
                        continue

                    if cALLID not in VIDEO_CALL_ROOMS:
                        continue

                    rOOM = VIDEO_CALL_ROOMS[cALLID]
                    pARTICIPANTS = rOOM["participants"]

                    '''Find the receiver socket based on the socket id'''
                    tARGETSOCKET = None

                    for sOCK, iNFO in pARTICIPANTS.items():
                        if iNFO.get("socketId") == tARGETSOCKETID:
                            tARGETSOCKET = sOCK
                            break

                    if not tARGETSOCKET:
                        continue

                    '''Forward the message with the senders socketId and username'''
                    sENDERID = SOCKET_IDS.get(handler.request)
                    sENDERNAME = SOCKET_USERNAMES.get(handler.request, "Guest")

                    fORWARDMESSAGE = {}
                    fORWARDMESSAGE["messageType"] = mESSAGETYPE
                    fORWARDMESSAGE["socketId"] = sENDERID
                    fORWARDMESSAGE["username"] = sENDERNAME

                    '''Copy the webrtc data fields'''
                    if "offer" in mESSAGE:
                        fORWARDMESSAGE["offer"] = mESSAGE.get("offer")
                    if "answer" in mESSAGE:
                        fORWARDMESSAGE["answer"] = mESSAGE.get("answer")
                    if "candidate" in mESSAGE:
                        fORWARDMESSAGE["candidate"] = mESSAGE.get("candidate")

                    fORWARDPAYLOAD = json.dumps(fORWARDMESSAGE).encode()
                    fORWARDFRAME = generate_ws_frame(fORWARDPAYLOAD)

                    try:
                        tARGETSOCKET.sendall(fORWARDFRAME)
                    except Exception:
                        pass

                elif mESSAGETYPE == "get_all_users":

                    '''Store a list of all registered users'''
                    aLLUSERSLIST = []

                    '''Go through each registered user in the database'''
                    for uSER in rEGISTERDATA.find({}):

                        uSERNAME = uSER.get("username")

                        if uSERNAME:
                            aLLUSERSLIST.append({"username": uSERNAME})

                    '''Turn the list into a json string and store as payload with the messageType'''
                    aLLUSERSpayload = json.dumps({"messageType": "all_users_list", "users": aLLUSERSLIST}).encode()

                    '''Make a websocket frame'''
                    aLLUSERSframe = generate_ws_frame(aLLUSERSpayload)

                    try:
                        handler.request.sendall(aLLUSERSframe)
                    except Exception:
                        pass


                elif mESSAGETYPE == "select_user":

                    '''Get the selected user'''
                    tARGETUSER = mESSAGE.get("targetUser")

                    if not tARGETUSER:
                        continue

                    '''Get my username'''
                    mYUSERNAME = SOCKET_USERNAMES.get(handler.request, "Guest")

                    '''Store the message history between me and the selected user'''
                    mESSAGEHISTORY = []

                    '''Query for both directions (me -> them) OR (them -> me)'''
                    qUERY = {"$or": [{"fromUser": mYUSERNAME, "toUser": tARGETUSER},{"fromUser": tARGETUSER, "toUser": mYUSERNAME}]}

                    '''Add each message to mESSAGEHISTORY'''
                    for dM in dIRECTMESSAGEDATA.find(qUERY).sort("createdAt", 1).limit(50):
                        mESSAGEHISTORY.append({"fromUser": dM.get("fromUser"),"toUser": dM.get("toUser"),"text": dM.get("text", "") })

                    '''Turn history into a json string and store as payload with the messageType'''
                    hISTORYpayload = json.dumps({"messageType": "message_history", "messages": mESSAGEHISTORY}).encode()

                    '''Make a websocket frame'''
                    hISTORYframe = generate_ws_frame(hISTORYpayload)

                    try:

                        handler.request.sendall(hISTORYframe)

                    except Exception:

                        pass

                elif mESSAGETYPE == "direct_message":

                    '''Get the target user and text'''
                    tARGETUSER = mESSAGE.get("targetUser")
                    tEXT = mESSAGE.get("text", "")

                    if (not tARGETUSER) or (tEXT == ""):
                        continue

                    '''Get my username'''
                    fROMUSER = SOCKET_USERNAMES.get(handler.request, "Guest")

                    '''Store the direct message in the database'''
                    nEWDIRECTMESSAGE = {
                        "fromUser": fROMUSER,
                        "toUser": tARGETUSER,
                        "text": tEXT,
                        "createdAt": time.time()
                    }

                    dIRECTMESSAGEDATA.insert_one(nEWDIRECTMESSAGE)

                    '''Send the message back to the sender and also to the receiver if online'''
                    oUTPAYLOAD = json.dumps({
                        "messageType": "direct_message",
                        "fromUser": fROMUSER,
                        "toUser": tARGETUSER,
                        "text": tEXT
                    }).encode()

                    oUTFRAME = generate_ws_frame(oUTPAYLOAD)

                    '''Send to the sender'''
                    try:
                        handler.request.sendall(oUTFRAME)
                    except Exception:
                        pass

                    '''Send to the receiver if they are connected'''
                    for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:

                        if cLIENT.get("username") == tARGETUSER:

                            try:
                                cLIENT["socket"].sendall(oUTFRAME)
                            except Exception:
                                pass

                            break

    if cONNECTIONCLOSED:

        '''If the user was in a video call, tell the room they left'''
        if handler.request in SOCKET_TO_CALL:

            cALLID = SOCKET_TO_CALL.get(handler.request)
            SOCKET_TO_CALL.pop(handler.request, None)

            if cALLID in VIDEO_CALL_ROOMS:

                rOOM = VIDEO_CALL_ROOMS[cALLID]
                pARTICIPANTS = rOOM["participants"]

                iNFO = pARTICIPANTS.pop(handler.request, None)

                if iNFO:
                    lEFTSOCKETID = iNFO.get("socketId")

                    uSERLEFTPAYLOAD = json.dumps({"messageType": "user_left", "socketId": lEFTSOCKETID}).encode()
                    uSERLEFTFRAME = generate_ws_frame(uSERLEFTPAYLOAD)

                    for sOCK in pARTICIPANTS:
                        try:
                            sOCK.sendall(uSERLEFTFRAME)
                        except Exception:
                            pass

        SOCKET_IDS.pop(handler.request, None)
        SOCKET_USERNAMES.pop(handler.request, None)

        '''Make a new list of active users without the disconected user'''
        nEWACTIVEUSERSLIST = []

        for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:

            if cLIENT["socket"] != handler.request:
                nEWACTIVEUSERSLIST.append(cLIENT)

        '''Clear the old aCTIVECLIENTLIST'''
        MyTCPHandler.aCTIVECLIENTLIST.clear()

        '''Add each connected user back to the list of active clients'''
        for uSER in nEWACTIVEUSERSLIST:
            MyTCPHandler.aCTIVECLIENTLIST.append(uSER)

        '''Clear the old aCTIVEUSERSLIST and start anew'''
        aCTIVEUSERSLIST = []

        '''Go through each of the clients in the active client list'''
        for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:

            '''Store each username in aCTIVEUSERSLIST'''
            if cLIENT["username"]:
                aCTIVEUSERSLIST.append({"username": cLIENT["username"]})

        '''Turn the new list of aCTIVEUSERSLIST into a json string and store as payload with the messageType'''
        nEWBROADCASTPAYLOAD = json.dumps({"messageType": "active_users_list", "users": aCTIVEUSERSLIST}).encode()

        '''Make a websocket frame'''
        nEWBROADCASTWEBFRAME = generate_ws_frame(nEWBROADCASTPAYLOAD)

        '''Go through each of the clients in the active client list and send the websocket frame to the client'''
        for cLIENT in MyTCPHandler.aCTIVECLIENTLIST:
            try:
                cLIENT["socket"].sendall(nEWBROADCASTWEBFRAME)
            except Exception:
                pass



def pOSTVIDEOCALL(request, handler):
    '''Get the jwt payload data'''
    uSER = gETJWTUSER(request, handler)

    if not uSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no jwt")

        handler.request.sendall(rESPONCE.to_data())

        return

    '''Find the user in the registered database'''
    rEGISTEREDUSER = rEGISTERDATA.find_one({"id": uSER["id"]})

    if not rEGISTEREDUSER:
        rESPONCE = Response()
        rESPONCE.set_status(401, "Unauthorized")
        rESPONCE.text("no registered user")
        handler.request.sendall(rESPONCE.to_data())
        return

    try:

        bODY = json.loads(request.body.decode())

    except:
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("invalid json")
        handler.request.sendall(rESPONCE.to_data())
        return

    nAME = (bODY.get("name") or "").strip()
    if nAME == "":
        rESPONCE = Response()
        rESPONCE.set_status(400, "Bad Request")
        rESPONCE.text("missing name")
        handler.request.sendall(rESPONCE.to_data())
        return

    cALLID = uuid.uuid4().hex
    vIDEOCALLDATA.insert_one({"id": cALLID, "name": nAME})

    rESPONCE = Response()
    rESPONCE.json({"id": cALLID})

    handler.request.sendall(rESPONCE.to_data())


class MyTCPHandler(socketserver.BaseRequestHandler):
    aCTIVECLIENTLIST = []

    def __init__(self, request, client_address, server):
        self.router = Router()
        self.router.add_route("GET", "/hello", hello_path, True)
        # TODO: Add your routes here

        self.router.add_route("GET", "/public", fINDPUBLIC)
        self.router.add_route("GET", "/", mOVETOHOME, True)
        self.router.add_route("GET", "/chat", mOVETOCHAT, True)
        self.router.add_route("POST", "/api/chats", pOSTCHAT, True)
        self.router.add_route("GET", "/api/chats", gETCHAT, True)
        self.router.add_route("PATCH", "/api/chats/", pATCHCHAT)
        self.router.add_route("DELETE", "/api/chats/", dELETECHAT)
        self.router.add_route("GET", "/settings", mOVETOSETTINGS, True)
        self.router.add_route("GET", "/search-users", mOVETOSEARCHUSERS, True)
        self.router.add_route("GET", "/api/users/@me", gETME, True)
        self.router.add_route("GET", "/api/users/search", gETSEARCHUSERS)
        self.router.add_route("POST", "/api/users/settings", pOSTUPDATEPROFILESETTINGS,True)
        self.router.add_route("POST", "/api/users/regenerate-2fa", pOSTGENERATE2FA, True)
        self.router.add_route("POST", "/api/users/avatar", pOSTAVATARUPLOAD, True)
        self.router.add_route("GET", "/change-avatar", mOVETOCHANGEAVATAR, True)
        self.router.add_route("GET", "/videotube", mOVETOVIDEOTUBE, True)
        self.router.add_route("GET", "/videotube/upload", mOVETOVIDEOTUBEUPLOAD, True)
        self.router.add_route("GET", "/videotube/videos/", mOVETOVIDEO)
        self.router.add_route("POST", "/api/videos", pOSTUPLOADVIDEOS, True)
        self.router.add_route("GET", "/api/videos", gETVIDEOS, True)
        self.router.add_route("GET", "/api/videos/", gETVIDEOSVIDEOID)
        self.router.add_route("GET", "/videotube/set-thumbnail", mOVETOSETTHUMBNAIL)
        self.router.add_route("PUT", "/api/thumbnails/", pUTTHUMBNAIL)
        self.router.add_route("GET", "/test-websocket", mOVETOTESTWEBSOCKET, True)
        self.router.add_route("GET", "/drawing-board", mOVETODRAWINGBOARD, True)
        self.router.add_route("GET", "/websocket", gETWEBSOCKET, True)
        self.router.add_route("GET", "/direct-messaging", mOVETODIRECTMESSAGING, True)
        self.router.add_route("GET", "/video-call", mOVETOVIDEOCALL, True)
        self.router.add_route("GET", "/video-call/", mOVETOVIDEOCALLROOM)
        self.router.add_route("GET", "/videotube/view-video", mOVETOVIEWVIDEO, True)
        self.router.add_route("POST", "/api/video-calls", pOSTVIDEOCALL, True)

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
    port = 8080
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    server = socketserver.ThreadingTCPServer((host, port), MyTCPHandler)

    print("Listening on port " + str(port))
    server.serve_forever()


if __name__ == "__main__":
    main()
