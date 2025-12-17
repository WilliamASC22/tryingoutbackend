def extract_credentials(request):

    '''Get the body'''
    bODY = request.body.decode()

    '''Spit on &, septerate user and pass'''
    uSERNAMEpassword = bODY.split("&")

    sTORE = {}


    '''Look through username first then password'''
    for uP in uSERNAMEpassword:
        if "=" in uP:

            '''Split on the first = so we can go throguh the value of the username and password'''
            kEY, vALUE = uP.split("=", 1)

            '''Replace the + with space'''
            vALUE = vALUE.replace("+", " ")


            sTORAGE = ""

            x = 0


            while x < len(vALUE):

                if (vALUE[x] == "%") and ((x + 2) < len(vALUE)):

                    '''Get the two values after the %'''
                    hEX1 = vALUE[x+1]
                    hEX2 = vALUE[x+2]

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

                        sTORAGE = sTORAGE + vALUE[x]
                        x = x + 1

                else:

                    sTORAGE = sTORAGE + vALUE[x]
                    x = x + 1


            '''Strip new line'''
            sTORAGE = sTORAGE.strip("\r\n")

            sTORE[kEY] = sTORAGE

    uSERNAME = sTORE.get("username", "")
    pASSWORD = sTORE.get("password", "")

    '''Get the totp if it is there'''
    tOTP = sTORE.get("totp", "")

    return [uSERNAME, pASSWORD, tOTP]

def validate_password(sTRING):

    '''Check if the password is at least 8 characters'''
    if len(sTRING) < 8:
        return False

    '''Make sure each flag is true'''
    lOWERCASELETTEREXISTS = False
    uPPERCASELETTEREXISTS = False
    nUMBEREXISTS = False
    aSPECIALCHARACTEREXISTS = False

    sPECIALCHARACTERS = "!@#$%^&()-_="

    '''Check what the character is'''
    for s in sTRING:

        if s.islower():
            lOWERCASELETTEREXISTS = True

        elif s.isupper():
            uPPERCASELETTEREXISTS = True

        elif s.isdigit():
            nUMBEREXISTS = True

        elif s in sPECIALCHARACTERS:
            aSPECIALCHARACTEREXISTS = True


        else:
            '''Invalid character exits'''
            return False

    '''If all the flags are true return true'''
    if lOWERCASELETTEREXISTS:
        if uPPERCASELETTEREXISTS:
            if nUMBEREXISTS:
                if aSPECIALCHARACTEREXISTS:
                    return True

    '''If all of the flags are not true return false'''
    return False





