import hashlib
import base64

def compute_accept(sECwebsocketKEY):

    '''Add the guid to the key'''
    kEYGUID = sECwebsocketKEY + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    '''Encode the key and guid, then hash it, then turn it into bytes'''
    hASHEDkeyguid = hashlib.sha1(kEYGUID.encode()).digest()
    '''Use base64 to encode the hash bytes and turn it into a string'''
    bACE64encodedHASH = base64.b64encode(hASHEDkeyguid).decode()

    return bACE64encodedHASH

class wEBSOCKETFRAME:

    def __init__(self, fin_bit, opcode, payload_length, payload):
        self.fin_bit = fin_bit
        self.opcode = opcode
        self.payload_length = payload_length
        self.payload = payload


def parse_ws_frame(fRAMEBYTES):

    '''If there are not at least 2 bytes the frame is improper'''
    if len(fRAMEBYTES) < 2:
        raise ValueError

    '''Store the first byte. It has FIN bit, RSV1, RSV2, RSV3, opcode (the type)'''
    bYTE1 = fRAMEBYTES[0]
    '''Store the second byte. It has the MASK and Payloadlen'''
    bYTE2 = fRAMEBYTES[1]

    '''Get the opcode by using bitwise AND on bYTE1 with 15 that means 00001111 like in slides'''
    oPCODE = bYTE1 & 15

    '''Get the fIN bit by moving the bits 7 places to the right then using bitwise AND with 1 which means 00000001'''
    fINBIT = bYTE1 >> 7
    fINBIT = fINBIT & 1

    '''Get the MASk bit with the same strat as the FIN bit but with bYTE2'''
    mASKBIT = bYTE2 >> 7
    mASKBIT = mASKBIT & 1

    '''Get the payload len by using bitwise AND on byte2 with 127 that means 01111111 so the bit on the left for MASK is cleared'''
    pAYLOADLEN = bYTE2 & 127

    '''If the payload len is exactly 126 then the next two bytes store the actual length
        If the payload len is exactly 127 then the next eight bytes store the actual length'''
    nOW = 2
    if pAYLOADLEN == 126:

        if len(fRAMEBYTES) < nOW + 2:
            raise ValueError

        '''Get the next two bytes'''
        fUTUREBYTE1 = fRAMEBYTES[nOW]
        fUTUREBYTE2 = fRAMEBYTES[nOW+1]

        '''Move the bytes in fUTUREBYTE1 to the left 8 bits to make room and add fUTUREBYTE2 so we have 16 bits'''
        pAYLOADLEN = (fUTUREBYTE1 << 8 ) + fUTUREBYTE2

        nOW = nOW + 2

    elif pAYLOADLEN == 127:

        if len(fRAMEBYTES) < nOW + 8:
            raise ValueError

        '''Get the next eight bytes'''
        fUTUREBYTE1 = fRAMEBYTES[nOW]
        fUTUREBYTE2 = fRAMEBYTES[nOW+1]
        fUTUREBYTE3 = fRAMEBYTES[nOW+2]
        fUTUREBYTE4 = fRAMEBYTES[nOW+3]
        fUTUREBYTE5 = fRAMEBYTES[nOW+4]
        fUTUREBYTE6 = fRAMEBYTES[nOW+5]
        fUTUREBYTE7 = fRAMEBYTES[nOW+6]
        fUTUREBYTE8 = fRAMEBYTES[nOW+7]

        '''Each byte is 8 bits so we have to move the first 56, then the second byte 48 and add it, then ...'''
        pAYLOADLEN = (fUTUREBYTE1 << 56 ) + (fUTUREBYTE2 << 48 ) + (fUTUREBYTE3 << 40) + (fUTUREBYTE4 << 32) + (fUTUREBYTE5 << 24) + (fUTUREBYTE6 << 16) + (fUTUREBYTE7 << 8) + fUTUREBYTE8

        nOW = nOW + 8

    '''Store the mask bytes'''
    tHEMASKBYTES = []
    '''If the MASK bit is 1 then the next four bytes store the MASK'''
    if mASKBIT == 1:

        if len(fRAMEBYTES) < nOW + 4:
            raise ValueError

        '''Get the next four bytes'''
        fUTUREBYTE1 = fRAMEBYTES[nOW]
        fUTUREBYTE2 = fRAMEBYTES[nOW+1]
        fUTUREBYTE3 = fRAMEBYTES[nOW+2]
        fUTUREBYTE4 = fRAMEBYTES[nOW+3]

        '''Add the next four bytes to our list of mask'''
        tHEMASKBYTES.append(fUTUREBYTE1)
        tHEMASKBYTES.append(fUTUREBYTE2)
        tHEMASKBYTES.append(fUTUREBYTE3)
        tHEMASKBYTES.append(fUTUREBYTE4)

        nOW = nOW + 4

    '''If the amount of bytes in this frame is less than amount of bytes of the header + the expected amount of bytes for the message then it is improper'''
    if (len(fRAMEBYTES) < nOW + pAYLOADLEN):
        raise ValueError

    '''Get the payload bytes that are everything after the MASK bytes if there is a MASK'''
    pAYLOADBYTES = fRAMEBYTES[nOW: nOW + pAYLOADLEN]

    '''If the MASK bit is 1 then read every 4 bytes of pAYLOADBYTES by XORing with tHEMASKBYTES'''
    if mASKBIT == 1:

        '''Store the unmasked bytes'''
        uNMASKEDBYTES = []

        '''The number of content byte we are on'''
        bYTE = 0

        '''The mask byte for the byte we are unmasking now'''
        mASKbyteNOW = 0

        '''Go through the each of the bytes in pAYLOADLEN'''
        while bYTE < pAYLOADLEN:
            '''The byte we are going to unmask'''
            mASKEDBYTE = pAYLOADBYTES[bYTE]
            '''The mask byte we are going to XOR with'''
            mASKNOW = tHEMASKBYTES[mASKbyteNOW]

            '''XOR mASKEDBYTE with mASKNOW'''
            uNMASKED = mASKEDBYTE ^ mASKNOW
            '''Store the unmasked byte in uNMASKEDBYTES'''
            uNMASKEDBYTES.append(uNMASKED)

            bYTE = bYTE + 1

            '''Move the mask byte to the next byte. If it is 4 we reset it to 0'''
            mASKbyteNOW = mASKbyteNOW + 1

            if mASKbyteNOW == 4:
                mASKbyteNOW = 0

        pAYLOADBYTES = bytes(uNMASKEDBYTES)

    return wEBSOCKETFRAME(fINBIT, oPCODE, pAYLOADLEN, pAYLOADBYTES)

def parse_ws_frames(fRAMEBYTES):

    fRAMES = []
    iNDEX = 0
    tOTALLEN = len(fRAMEBYTES)

    while True:
        '''If there are not at least 2 bytes the frame is improper'''
        if (tOTALLEN - iNDEX) < 2:
            break

        '''Store the first byte. It has FIN bit, RSV1, RSV2, RSV3, opcode (the type)'''
        bYTE1 = fRAMEBYTES[iNDEX]
        '''Store the second byte. It has the MASK and Payloadlen'''
        bYTE2 = fRAMEBYTES[iNDEX + 1]

        '''Get the opcode by using bitwise AND on bYTE1 with 15 that means 00001111 like in slides'''
        oPCODE = bYTE1 & 15

        '''Get the fIN bit by moving the bits 7 places to the right then using bitwise AND with 1 which means 00000001'''
        fINBIT = bYTE1 >> 7
        fINBIT = fINBIT & 1

        '''Get the MASk bit with the same strat as the FIN bit but with bYTE2'''
        mASKBIT = bYTE2 >> 7
        mASKBIT = mASKBIT & 1

        '''Get the payload len by using bitwise AND on byte2 with 127 that means 01111111 so the bit on the left for MASK is cleared'''
        pAYLOADLEN = bYTE2 & 127

        '''If the payload len is exactly 126 then the next two bytes store the actual length
            If the payload len is exactly 127 then the next eight bytes store the actual length'''
        nOW = iNDEX + 2
        if pAYLOADLEN == 126:

            if tOTALLEN < nOW + 2:
                break

            '''Get the next two bytes'''
            fUTUREBYTE1 = fRAMEBYTES[nOW]
            fUTUREBYTE2 = fRAMEBYTES[nOW+1]

            '''Move the bytes in fUTUREBYTE1 to the left 8 bits to make room and add fUTUREBYTE2 so we have 16 bits'''
            pAYLOADLEN = (fUTUREBYTE1 << 8 ) + fUTUREBYTE2

            nOW = nOW + 2

        elif pAYLOADLEN == 127:

            if tOTALLEN < nOW + 8:
                break

            '''Get the next eight bytes'''
            fUTUREBYTE1 = fRAMEBYTES[nOW]
            fUTUREBYTE2 = fRAMEBYTES[nOW+1]
            fUTUREBYTE3 = fRAMEBYTES[nOW+2]
            fUTUREBYTE4 = fRAMEBYTES[nOW+3]
            fUTUREBYTE5 = fRAMEBYTES[nOW+4]
            fUTUREBYTE6 = fRAMEBYTES[nOW+5]
            fUTUREBYTE7 = fRAMEBYTES[nOW+6]
            fUTUREBYTE8 = fRAMEBYTES[nOW+7]

            '''Each byte is 8 bits so we have to move the first 56, then the second byte 48 and add it, then ...'''
            pAYLOADLEN = (fUTUREBYTE1 << 56 ) + (fUTUREBYTE2 << 48 ) + (fUTUREBYTE3 << 40) + (fUTUREBYTE4 << 32) + (fUTUREBYTE5 << 24) + (fUTUREBYTE6 << 16) + (fUTUREBYTE7 << 8) + fUTUREBYTE8

            nOW = nOW + 8

        '''Store the mask bytes'''
        tHEMASKBYTES = []
        '''If the MASK bit is 1 then the next four bytes store the MASK'''
        if mASKBIT == 1:

            if tOTALLEN < nOW + 4:
                break

            '''Get the next four bytes'''
            fUTUREBYTE1 = fRAMEBYTES[nOW]
            fUTUREBYTE2 = fRAMEBYTES[nOW+1]
            fUTUREBYTE3 = fRAMEBYTES[nOW+2]
            fUTUREBYTE4 = fRAMEBYTES[nOW+3]

            '''Add the next four bytes to our list of mask'''
            tHEMASKBYTES.append(fUTUREBYTE1)
            tHEMASKBYTES.append(fUTUREBYTE2)
            tHEMASKBYTES.append(fUTUREBYTE3)
            tHEMASKBYTES.append(fUTUREBYTE4)

            nOW = nOW + 4

        '''If the amount of bytes in this frame is less than amount of bytes of the header + the expected amount of bytes for the message then it is improper'''
        if (tOTALLEN < nOW + pAYLOADLEN):
            break

        '''Get the payload bytes that are everything after the MASK bytes if there is a MASK'''
        pAYLOADBYTES = fRAMEBYTES[nOW: nOW + pAYLOADLEN]

        '''If the MASK bit is 1 then read every 4 bytes of pAYLOADBYTES by XORing with tHEMASKBYTES'''
        if mASKBIT == 1:

            '''Store the unmasked bytes'''
            uNMASKEDBYTES = []

            '''The number of content byte we are on'''
            bYTE = 0

            '''The mask byte for the byte we are unmasking now'''
            mASKbyteNOW = 0

            '''Go through the each of the bytes in pAYLOADLEN'''
            while bYTE < pAYLOADLEN:
                '''The byte we are going to unmask'''
                mASKEDBYTE = pAYLOADBYTES[bYTE]
                '''The mask byte we are going to XOR with'''
                mASKNOW = tHEMASKBYTES[mASKbyteNOW]

                '''XOR mASKEDBYTE with mASKNOW'''
                uNMASKED = mASKEDBYTE ^ mASKNOW
                '''Store the unmasked byte in uNMASKEDBYTES'''
                uNMASKEDBYTES.append(uNMASKED)

                bYTE = bYTE + 1

                '''Move the mask byte to the next byte. If it is 4 we reset it to 0'''
                mASKbyteNOW = mASKbyteNOW + 1

                if mASKbyteNOW == 4:
                    mASKbyteNOW = 0

            pAYLOADBYTES = bytes(uNMASKEDBYTES)

        fRAMES.append(wEBSOCKETFRAME(fINBIT, oPCODE, pAYLOADLEN, pAYLOADBYTES))

        iNDEX = nOW + pAYLOADLEN

    rEMAINING = fRAMEBYTES[iNDEX:]
    return fRAMES, rEMAINING

def generate_ws_frame(pAYLOAD):

    '''Store the FIN bit of 1 and an opcode of 0b0001'''
    fINBITandOPCODE = 128 + 1
    '''Store the fINBITandOPCODE as bytes in the hEADER'''
    hEADER = bytes([fINBITandOPCODE])

    '''Get the length of the payload'''
    pAYLOADLENGTH = len(pAYLOAD)

    '''If the payload length is less than 126 we store the length of the payload as bytes after the fINBITandOPCODE.
        If the payload length is between 126 and 65535 then we put 126 and put the actual length is in the next two bytes.
        If the payload length is over 65535 we put 127 and the actual length is in the next eight bytes.'''
    if pAYLOADLENGTH < 126:
        hEADER = hEADER + bytes([pAYLOADLENGTH])

    elif pAYLOADLENGTH < 65536:

        hEADER = hEADER + bytes([126])

        '''Shift the right most 8 bits off so we are left with only the left most 8 bits'''
        bYTE1 = pAYLOADLENGTH >> 8
        '''Store the first byte in the header'''
        hEADER = hEADER + bytes([bYTE1])

        '''Use bitwise AND on pAYLOADLENGTH with 255 which is 00000000 11111111 to clear the 8 leftmost bits'''
        bYTE2 = pAYLOADLENGTH & 255
        '''Store the second byte in the header'''
        hEADER = hEADER + bytes([bYTE2])

    else:

        hEADER = hEADER + bytes([127])

        '''Shift the right most 56 bits off so we are left with only the left most 8 bits, Shift the right most 48 bits off so we are left with only the left most 8 bits, ...
        Then use bitwise AND to clear the bits on the right that are not part of the 8 bits we are storing'''
        bYTE1 = (pAYLOADLENGTH >> 56) & 255
        bYTE2 = (pAYLOADLENGTH >> 48) & 255
        bYTE3 = (pAYLOADLENGTH >> 40) & 255
        bYTE4 = (pAYLOADLENGTH >> 32) & 255
        bYTE5 = (pAYLOADLENGTH >> 24) & 255
        bYTE6 = (pAYLOADLENGTH >> 16) & 255
        bYTE7 = (pAYLOADLENGTH >> 8) & 255
        bYTE8 = pAYLOADLENGTH & 255

        '''Store the bytes in the hEADER'''
        hEADER = hEADER + bytes([bYTE1])
        hEADER = hEADER + bytes([bYTE2])
        hEADER = hEADER + bytes([bYTE3])
        hEADER = hEADER + bytes([bYTE4])
        hEADER = hEADER + bytes([bYTE5])
        hEADER = hEADER + bytes([bYTE6])
        hEADER = hEADER + bytes([bYTE7])
        hEADER = hEADER + bytes([bYTE8])

    wEBsocketFRAME = hEADER + pAYLOAD

    return wEBsocketFRAME

