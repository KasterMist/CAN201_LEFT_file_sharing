from Crypto.Util.Padding import unpad
from LEFT_file_sharing.tool import *
import math
from tqdm import tqdm
from socket import *


# This function aims to download files which peer does not have
def downloader(filename, total_size, client_socket, file_exist_flag):
    path, file1 = os.path.split(filename)
    if not path == '':
        flag = os.path.exists(path)
        if not flag:
            os.makedirs(path)
    total_block_number = math.ceil(total_size / block_size)
    file = open(filename + '.lefting', 'wb')
    file.seek(total_size - 1)
    file.write(b'0')
    file.close()
    file = open(filename + '.lefting', 'wb')
    for block_index in tqdm(range(total_block_number)):
        file_exist_flag_b = struct.pack('!I', file_exist_flag)
        client_socket.send(file_exist_flag_b)
        request = ask_file_block(filename, block_index)
        client_socket.send(request)
        block_header = client_socket.recv(8)
        block_index, block_length = struct.unpack('!II', block_header)
        buf = b''
        while len(buf) < block_length:
            buf += client_socket.recv(block_length)
        file_block = buf[:block_length]
        if encryption_flag:
            key = file_block[:16]
            iv = file_block[16:32]
            file_block_en = file_block[32:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            file_block = unpad(cipher.decrypt(file_block_en), AES.block_size)

        download_file_block(file, block_index, file_block)
    file.close()

    os.rename(filename + '.lefting', filename)
    file_finish_flag = 1
    file_finish_flag_b = struct.pack('!I', file_finish_flag)
    client_socket.send(file_finish_flag_b)


# This function would be called when the certain has not already been transmitted yet
def adder(filename, total_size, client_socket, file_exist_flag):
    file_size = get_file_size(filename + '.lefting')
    origin_block_index = math.floor(file_size / block_size)
    total_block_number = math.ceil(total_size / block_size)
    file = open(filename + '.lefting', 'ab')
    for block_index in tqdm(range(origin_block_index, total_block_number)):
        file_exist_flag_b = struct.pack('!I', file_exist_flag)
        client_socket.send(file_exist_flag_b)
        request = ask_file_block(filename, block_index)
        client_socket.send(request)
        block_header = client_socket.recv(8)
        block_index, block_length = struct.unpack('!II', block_header)
        buf = b''
        while len(buf) < block_length:
            buf += client_socket.recv(block_length)
        file_block = buf[:block_length]
        if encryption_flag:
            key = file_block[:16]
            iv = file_block[16:32]
            file_block_en = file_block[32:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            file_block = unpad(cipher.decrypt(file_block_en), AES.block_size)

        download_file_block(file, block_index, file_block)
    file.close()
    os.rename(filename + '.lefting', filename)

    file_finish_flag = 1
    file_finish_flag_b = struct.pack('!I', file_finish_flag)
    client_socket.send(file_finish_flag_b)


# This function would be called if the files are updated
def updater(filename, total_size, client_socket, file_exist_flag):
    total_block_number = math.ceil(total_size / block_size)
    part_block_number = math.ceil(total_block_number / 100)
    os.rename(filename, filename + '.lefting')
    file = open(filename + '.lefting', 'rb+')
    for block_index in tqdm(range(part_block_number)):
        file_exist_flag_b = struct.pack('!I', file_exist_flag)
        client_socket.send(file_exist_flag_b)
        request = ask_file_block(filename, block_index)
        client_socket.send(request)
        block_header = client_socket.recv(8)
        block_index, block_length = struct.unpack('!II', block_header)
        buf = b''
        while len(buf) < block_length:
            buf += client_socket.recv(block_length)
        file_block = buf[:block_length]
        if encryption_flag:
            key = file_block[:16]
            iv = file_block[16:32]
            file_block_en = file_block[32:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            file_block = unpad(cipher.decrypt(file_block_en), AES.block_size)

        download_file_block(file, block_index, file_block)
    file.close()
    os.rename(filename + '.lefting', filename)
    file_finish_flag = 1
    file_finish_flag_b = struct.pack('!I', file_finish_flag)
    client_socket.send(file_finish_flag_b)


def tcp_scanner(server_socket):
    while True:
        new_socket, client_addr = server_socket.accept()
        while True:
            try:
                server_file_list = traverse('share')
                for filename in server_file_list:
                    file_info = make_file_information(filename)
                    new_socket.send(file_info)
                    while True:
                        flag_b = new_socket.recv(4)
                        flag = struct.unpack('!I', flag_b)[0]
                        if flag == 1:
                            break
                        else:
                            message = new_socket.recv(1024)
                            file_block = send_file_block(message)
                            new_socket.send(file_block)
            except:
                break


def tcp_obtainer(server_name, server_port, client_port):
    # Trying to connect the server, until it is connected
    while True:
        while True:
            try:
                client_socket = socket(AF_INET, SOCK_STREAM)
                client_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                client_socket.bind(('', client_port))
                client_socket.connect((server_name, server_port))
                break
            except:
                pass

        while True:
            try:
                file_detail, address = client_socket.recvfrom(10240)
                filename, total_size, md5, mtime = parse_file_information(file_detail)
                file_exist_flag = make_file_exist_flag(filename, md5, mtime)
                if file_exist_flag == 1:
                    file_exist_flag_b = struct.pack('!I', file_exist_flag)
                    client_socket.send(file_exist_flag_b)
                elif file_exist_flag == 0:
                    path, file1 = os.path.split(filename)
                    json_file = open(join('json', file1) + '.json', 'wb')
                    server_name_b = server_name.encode()
                    json_file.write(server_name_b)
                    json_file.close()
                    downloader(filename, total_size, client_socket, file_exist_flag)
                    os.remove(join('json', file1) + '.json')
                elif file_exist_flag == 2:
                    path, file1 = os.path.split(filename)
                    json_file = open(join('json', file1) + '.json', 'rb')
                    former_address = json_file.read().decode()
                    json_file.close()
                    if former_address == server_name:
                        adder(filename, total_size, client_socket, file_exist_flag)
                    os.remove(join('json', file1) + '.json')
                elif file_exist_flag == 3:
                    updater(filename, total_size, client_socket, file_exist_flag)
            except:
                break