
import argparse
import hashlib
import os
import struct
from os.path import *

import re

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


block_size = 1024 * 1024 * 4
encryption_flag = False


def _argparse():
    parser = argparse.ArgumentParser(description="This is description!")
    parser.add_argument('--ip', action='store', required=True, dest='ip', help='ip')
    parser.add_argument('--encryption', action='store', dest='encryption', help='encryption')
    return parser.parse_args()


def get_ip_address():
    parser = _argparse()
    ip_list = parser.ip.split(",")
    server_ip1 = ip_list[0]
    server_ip2 = ip_list[1]
    return server_ip1, server_ip2


def judge_encryption():
    global encryption_flag
    parser = _argparse()
    encryption = parser.encryption
    if encryption == 'yes':
        encryption_flag = True


# scan the certain folder and get every files' information except the files with ".lefting" as an end
def traverse(dir_file):
    flag = os.path.exists(dir_file)
    if not flag:
        os.mkdir(dir_file)
    file_list = []
    file_folder_list = os.listdir(dir_file)
    for file_folder_name in file_folder_list:
        result = re.match(r'.*\.lefting', file_folder_name)
        if result is None:
            if isfile(join(dir_file, file_folder_name)):
                file_list.append(join(dir_file, file_folder_name))
            else:
                file_list.extend(traverse(join(dir_file, file_folder_name)))
    return file_list


# Return the one block's md5 code
def get_file_md5(filename, file_index):
    f = open(filename, 'rb')
    f.seek(file_index * block_size)
    contents = f.read(block_size)
    f.close()
    return hashlib.md5(contents).hexdigest()


# get the file's mtime
def get_mtime(filename):
    return os.path.getmtime(filename)


# Return the file's total size
def get_file_size(filename):
    return os.path.getsize(filename)


# Make the file information. Return header, total size, filename, md5 and mtime
def make_file_information(filename):
    filename_b = filename.encode()
    filename_b_length = len(filename_b)
    total_size = get_file_size(filename)
    file_index = 0
    md5 = get_file_md5(filename, file_index)
    md5_b = md5.encode()
    mtime = get_mtime(filename)
    return struct.pack('!QQd', filename_b_length, total_size, mtime) + filename_b + md5_b


# Parse the file information. Return filename, total_size and its md5
def parse_file_information(file_detail):
    filename_b_length, total_size, mtime = struct.unpack('!QQd', file_detail[:24])
    filename_b = file_detail[24: 24 + filename_b_length]
    filename = filename_b.decode()
    md5 = file_detail[24 + filename_b_length:].decode()
    return filename, total_size, md5, mtime


# Check whether the file exist in the server or the same as the client's. Return a list of byte numbers
def make_file_exist_flag(filename, md5, mtime):
    # Flag 0 means that the file does not exist
    # Flag 1 means that the file is the same or the file(self) is updated
    # Flag 2 means that the file has not been already transmitted.
    # Flag 3 means that the file(other party) is updated.
    if not os.path.exists(filename):
        if not os.path.exists(filename + '.lefting'):
            file_exist_flag = 0
        else:
            file_exist_flag = 2
    else:
        file_index = 0
        original_file_md5 = get_file_md5(filename, file_index)
        if original_file_md5 == md5:
            file_exist_flag = 1
        else:
            file_mtime = get_mtime(filename)
            if file_mtime < mtime:
                file_exist_flag = 3
            else:
                file_exist_flag = 1

    return file_exist_flag


def ask_file_block(filename, block_index):
    filename_b = filename.encode()
    block_index_b = struct.pack('!I', block_index)
    return block_index_b + filename_b


def send_file_block(message):
    global block_size
    block_index_b = message[:4]
    block_index = struct.unpack('!I', block_index_b)[0]
    filename = message[4:].decode()
    file = open(filename, 'rb')
    file.seek(block_index * block_size)
    file_block = file.read(block_size)
    file.close()
    if encryption_flag:
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC)
        file_block = key + cipher.iv + cipher.encrypt(pad(file_block, AES.block_size))

    file_block_length = len(file_block)
    block_header = struct.pack('!II', block_index, file_block_length)
    return block_header + file_block


def download_file_block(file, block_index, message):
    global block_size
    file.seek(block_size * block_index)
    file.write(message)

