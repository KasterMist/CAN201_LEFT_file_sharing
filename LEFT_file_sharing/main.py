from LEFT_file_sharing.mode import *
from socket import *
import time

from threading import Thread

if __name__ == '__main__':
    if not os.path.exists('json'):
        os.makedirs('json')

    server_name1, server_name2 = get_ip_address()
    judge_encryption()
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('', 22000))
    server_socket.listen(128)

    ps1 = Thread(target=tcp_scanner, args=())
    ps2 = Thread(target=tcp_scanner, args=())
    pc1 = Thread(target=tcp_obtainer, args=(server_name1, 22000, 22002,))
    pc2 = Thread(target=tcp_obtainer, args=(server_name2, 22000, 22004,))
    while True:
        try:
            ps1.start()
            ps2.start()
            pc1.start()
            pc2.start()
        except:
            pass
        time.sleep(0.5)

