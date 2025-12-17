class Request:

    def __init__(self, request: bytes):
        # TODO: parse the bytes of the request and populate the following instance variables

        HEAD, BODY = self.makeHEADbody(request)

        self.body = BODY
        self.method = ""
        self.path = ""
        self.http_version = ""
        self.headers = {}
        self.cookies = {}

        if not HEAD:
            return

        HEADLINES = HEAD.split(b"\r\n")

        if not HEADLINES:
            return

        '''The first headline has these'''
        self.method, self.path, self.http_version = self.makeMETHODpathHTTPVERSION(HEADLINES[0])

        '''The headers start from the second line'''
        self.headers = self.makeHEADER(HEADLINES[1:])

        COOKIEHEADER = self.headers.get("Cookie")

        self.cookies = self.makeCOOKIE(COOKIEHEADER)

    def makeHEADbody(self, request: bytes):

        sPLITER = b"\r\n\r\n"

        '''splits the request into two parts, head and body at the place that the spliter is at'''
        headBODY = request.split(sPLITER, 1)

        '''the first half is the head'''
        HEAD = headBODY[0]

        '''the length of headBODY should be 2 if there is a body'''
        if len(headBODY) > 1:

            BODY = headBODY[1]

        else:

            BODY = b""

        return HEAD, BODY

    def makeMETHODpathHTTPVERSION(self, lINEBYTES: bytes):

        lINE = ""

        '''Make each byte into a character and store it into lINE'''
        for l in lINEBYTES:
            lINE = lINE + chr(l)

        '''Splits the line by whitespaces so it can be a space tab or a newline '''
        sPLITS = lINE.split()

        '''There should be 3 splits, the first is for method, the second is for path, and the third is for https version'''
        if len(sPLITS) == 3:
            mETHOD = sPLITS[0]
            PATH = sPLITS[1]

            hTTPVERSION = sPLITS[2]

            return mETHOD, PATH, hTTPVERSION

        '''sPLITS is not in three parts'''
        return "", "", ""

    def makeHEADER(self, lINEBYTES):

        '''Dictionary to store the headers that are found'''
        hEADERS = {}

        '''Look though each line'''
        for lBYTE in lINEBYTES:

            '''Make sure that it isnt empty and has :'''
            if lBYTE and b":" in lBYTE:

                '''Split the key and value pair at :'''
                kBYTE, vBYTE = lBYTE.split(b":", 1)

                '''Turn the key bytes into key characters'''
                kEY = ""

                for k in kBYTE:
                    kEY = kEY + chr(k)

                '''Strip whitespace if it exists'''
                kEY = kEY.strip()

                '''Turn the value bytes into vlaue characters'''
                vALUE = ""
                for v in vBYTE:
                    vALUE = vALUE + chr(v)

                '''Strip whitespace if it exists'''
                vALUE = vALUE.strip()

                hEADERS[kEY] = vALUE

        return hEADERS

    def makeCOOKIE(self, cOOKIEHEADER):
        '''Dictionary to store the cookies that are found'''
        cOOKIES = {}

        '''Make sure that it isnt empty'''
        if not cOOKIEHEADER:
            return cOOKIES

        '''Split the list of cookies into each cookies'''
        cOOKIESH = cOOKIEHEADER.split(";")

        for cOOKIE in cOOKIESH:

            '''Strip whitespace if it exists'''
            cOOKIE = cOOKIE.strip()

            if "=" in cOOKIE:
                '''Split the key value pairs at ='''
                kEY, vALUE = cOOKIE.split("=", 1)

                '''Remove whitespace and store in cookies'''
                kEY = kEY.strip()
                vALUE = vALUE.strip()
                cOOKIES[kEY] = vALUE

        return cOOKIES


def test1():
    request = Request(b'GET / HTTP/1.1\r\nHost: localhost:8080\r\nConnection: keep-alive\r\n\r\n')
    assert request.method == "GET"
    assert "Host" in request.headers
    assert request.headers["Host"] == "localhost:8080"  # note: The leading space in the header value must be removed
    assert request.body == b""  # There is no body for this request.
    # When parsing POST requests, the body must be in bytes, not str

    # This is the start of a simple way (ie. no external libraries) to test your code.
    # It's recommended that you complete this test and add others, including at least one
    # test using a POST request. Also, ensure that the types of all values are correct


if __name__ == '__main__':
    test1()
