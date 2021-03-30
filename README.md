# Requirement
This code is the coursework1 of CAN201 in XJTLU in 2020.
The project aims to using Python Socket network programming to implement “Large Efficient Flexible and Trusty (LEFT) Files Sharing”. The requirements are delivered below:
1.	Large: Any format of the files can be transmitted and the size can be up to 1GB.
2.	Efficient: The speed of file sharing should be fast enough and the changed files can be synchronized automatically. Partial updated is also allowed.
3.	Flexible: The IP addresses are arguments and the program can resume, if there is an interruption.
4.	Trusty: No error should be occurred. As one error occurs, the recovery should happen without retransmission. Data transmission security is also allowed.

# How to use
In three virtual machine, the file is the same. Run command: python3 main.py --ip <ipv4 addresses>, the documents in the "share" file will be synchronized.
For each virtual machine, the command will be started as: python3 main.py --ip 192.168.xxx.xxx,192.168.xxx.xxx
