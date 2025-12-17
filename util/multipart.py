class PART:

    def __init__(self, headers, name, content):

        self.headers = headers
        self.name = name
        self.content = content

class BOUNDARYPARTS:

    def __init__(self, boundary, parts):

        self.boundary = boundary
        self.parts = parts

def parse_multipart(request):
    '''Get the content type header'''
    cONTENTtypeHEADER = ""

    for kEY, vLAUE in request.headers.items():
        if kEY.lower() == "content-type":

            '''Store the content type header in cONTENTtypeHEADER'''
            cONTENTtypeHEADER = vLAUE

            break

    '''Get the boundary value'''
    bOUNDARYVALUE = ""

    '''Get the index of the boundary key, where the letter b is'''
    bOUNDARYINDEX = cONTENTtypeHEADER.find("boundary=")

    '''If it the boundary key is not there bOUNDARYINDEX is -1'''
    if bOUNDARYINDEX != -1:

        '''Get the start index of the boundary value'''
        iNDEXOFVALUESTART = bOUNDARYINDEX + len("boundary=")
        '''Get the end index of the boundary value'''
        iNDEXOFVALUEEND =  cONTENTtypeHEADER.find(";", iNDEXOFVALUESTART)

        '''If iNDEXOFVALUEEND is not found it is -1'''
        if iNDEXOFVALUEEND == -1:
            bOUNDARYVALUE = cONTENTtypeHEADER[iNDEXOFVALUESTART:]

        else:
            bOUNDARYVALUE = cONTENTtypeHEADER[iNDEXOFVALUESTART:iNDEXOFVALUEEND]

    bOUNDARYVALUE = bOUNDARYVALUE.strip().strip('"')

    '''Boundary value is not found'''
    if bOUNDARYVALUE == "":

        return BOUNDARYPARTS("",[])

    '''Make the boundary header bytes'''
    bOUNDARYHEADER = ("--" + bOUNDARYVALUE).encode()

    '''Get the parts of the boundarys by splitting with the boundary header bytes'''
    bOUNDARYPARTS = request.body.split(bOUNDARYHEADER)

    '''Store each part'''
    pARTS = []


    for bP in bOUNDARYPARTS:

        '''Look past spaces'''
        if bP.startswith(b"\r\n"):
            bP = bP[2:]

        elif bP.startswith(b"\n"):
            bP = bP[1:]

        '''-- is at supposed to be at the end'''
        if bP.startswith(b"--"):
            continue

        rNRN = b"\r\n\r\n"
        '''Get the index of \r\n\r\n before the content starts'''
        cONTENTstartsrnrnINDEX = bP.find(rNRN)


        '''If there is no \r\n\r\n skip'''
        if cONTENTstartsrnrnINDEX == -1:
            rNRN = b"\n\n"
            cONTENTstartsrnrnINDEX = bP.find(rNRN)
        '''The part isnt formated right'''
        if cONTENTstartsrnrnINDEX == -1:
            continue

        '''Use the cONTENTstartsrnINDEX to get the header bytes and content bytes'''
        hEADERBYTES = bP[:cONTENTstartsrnrnINDEX]
        cONTENTBYTES = bP[cONTENTstartsrnrnINDEX + len(rNRN):]

        '''Decode the headerbytes and split on the \r\n to get the header lines'''
        hEADERTEXT = hEADERBYTES.decode()
        hEADERLINES = hEADERTEXT.splitlines()

        '''Take off spaces at the end'''
        if cONTENTBYTES.endswith(b"\r\n"):
            cONTENTBYTES = cONTENTBYTES[:-2]

        elif cONTENTBYTES.endswith(b"\n"):
            cONTENTBYTES = cONTENTBYTES[:-1]

        '''Store the headers found'''
        hEADERS = {}

        for hL in hEADERLINES:

            '''Get the index of :'''
            cOLONINDEX = hL.find(":")

            '''If the : exists use it to get the key and value and store in hEADERS'''
            if cOLONINDEX != -1:

                kEY = hL[:cOLONINDEX].strip()

                vALUE = hL[cOLONINDEX + 1:].strip()

                if kEY != "":

                    hEADERS[kEY] = vALUE

        '''If the content disposition header exists store it'''
        cONTENTDISPOSITION = hEADERS.get("Content-Disposition", "")

        '''Store the name value'''
        nAMEVALUE = ""

        '''Get the index of the name key'''
        nAMEKEYINDEX = cONTENTDISPOSITION.find('name="')

        if nAMEKEYINDEX != -1:

            '''If the name key exists use it to find the " after the name value'''
            nAMEvalueOUOTEINDEX = cONTENTDISPOSITION.find('"', nAMEKEYINDEX + len('name="'))

            if nAMEvalueOUOTEINDEX != -1:

                '''If there is a quote after the name value then use it with the index of the name key to store the name value'''
                nAMEVALUE = cONTENTDISPOSITION[nAMEKEYINDEX + len('name="') :nAMEvalueOUOTEINDEX]

        '''Make a PART and store it in pARTS'''
        pARTS.append(PART(hEADERS, nAMEVALUE, cONTENTBYTES))


    return BOUNDARYPARTS(bOUNDARYVALUE, pARTS)

