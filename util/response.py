import json


class Response:
    def __init__(self):

        self.SETSTATUScode = 200
        self.SETSTATUStext = "OK"

        self.HEADERS = {}

        self.COOKIES = {}

        self.BODY = b""

    def set_status(self, code, text):

        self.SETSTATUScode = int(code)
        self.SETSTATUStext = str(text)

        return self

    def headers(self, headers):
        '''Store a list of the key value pairs'''
        hEADERSLIST = headers.items()

        '''Loop through the list of key value pairs'''
        for kEY, vALUE in hEADERSLIST:
            '''Make sure kEY is a string and clean the white space'''
            kEYSTRING = str(kEY)
            kEYSTRING = kEYSTRING.strip()

            '''Make sure vALUE is a string and clean the white space'''
            vALUESTRING = str(vALUE)
            vALUESTRING = vALUESTRING.strip()

            '''Store the kEY and vALUE in HEADERS'''
            self.HEADERS[kEYSTRING] = vALUESTRING

        return self

    def cookies(self, cookies):
        '''Store a list of the key value pairs'''
        cOOKIELIST = cookies.items()

        for kEY, vALUE in cOOKIELIST:
            '''Make sure kEY is a string and clean the white space'''
            kEYSTRING = str(kEY)
            kEYSTRING = kEYSTRING.strip()

            '''Make sure vALUE is a string and clean the white space'''
            vALUESTRING = str(vALUE)
            vALUESTRING = vALUESTRING.strip()

            '''Store the kEY and vALUE in COOKIES'''
            self.COOKIES[kEYSTRING] = vALUESTRING

        return self

    def bytes(self, data):


        self.BODY = self.BODY + data

        return self

    def text(self, data):

        '''Turn the text data into bytes before putting in the body'''
        dATABYTES = str(data).encode()

        self.BODY = self.BODY + dATABYTES
        return self


    def json(self, data):

        '''Turns json to string'''
        jsonSTRING = json.dumps(data)

        '''Turns json to bytes then puts it in the body'''
        jsonBYTES = jsonSTRING.encode()
        self.BODY = jsonBYTES

        '''Content type header'''
        self.HEADERS["Content-Type"] = "application/json"

        return self

    def to_data(self):

        '''Make the header'''
        hEADERHEAD = "HTTP/1.1 " + str(self.SETSTATUScode) + " " + self.SETSTATUStext + "\r\n"

        '''Set a defalt content type if there isnt already one'''
        if "Content-Type" not in self.HEADERS:
            self.HEADERS["Content-Type"] = "text/plain; charset=utf-8"

        '''Find the length of the body then put it as a string'''
        bODYLENGTH = len(self.BODY)
        self.HEADERS["Content-Length"] = str(bODYLENGTH)

        '''Turn off sniffing'''
        self.HEADERS["X-Content-Type-Options"] = "nosniff"

        '''Include the headers'''
        for kEY, vALUE in self.HEADERS.items():
            hEADERHEAD = hEADERHEAD + kEY + ": " + vALUE + "\r\n"

        '''Include the cookies'''
        for kEY, vALUE in self.COOKIES.items():
            hEADERHEAD = hEADERHEAD + "Set-Cookie: " + kEY + "=" + vALUE + "\r\n"

        '''Make hEADERHEAD into bytes and add a new line to seperate with body'''
        hEADERBYTES = hEADERHEAD.encode() + b"\r\n"

        return hEADERBYTES + self.BODY


def test1():
    res = Response()
    res.text("hello")
    expected = b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello'
    actual = res.to_data()


if __name__ == '__main__':
    test1()
