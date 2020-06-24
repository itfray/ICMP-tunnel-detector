# ICMP-tunnel-detector

## Overview

A program intercepts and analyzes ICMP packets from a network interface specified by a user.
If an ICMP tunnel is found, displays warning that contains IP addresses of hosts and possible process IDs.

## Requirements

- Python `^3.7.4`
- Pip `^19.0.3`
- Superuser privileges

## Installation

```bash
git clone https://github.com/itfray/ICMP-tunnel-detector.git
cd ./ICMP-tunnel-detector
```

* ### Windows

    ```bat
    python -m pip install -r requirements.txt
    ```

* ### Linux and MacOS

    ```bash
    python3 -m pip install -r requirements.txt
    ```

## Launch

* ### Windows

    ```bat
    python sniffer.py -la [ipv4 address]
    ```

* ### Linux and MacOS

    ```bash
    python3 sniffer.py -la [ipv4 address]
    ```

## Usage

    python sniffer.py -h
    usage: sniffer.py [-h] [-la LISTEN_ADDR] [-t TIMEOUT] [-f FILE] [-d]

    ICMP-tunneling: sniffer script

    options:
    -h, --help            show this help message and exit
    -la LISTEN_ADDR, --listen_addr LISTEN_ADDR
                            Specifies the interface's address that listen icmp-traffic
    -t TIMEOUT, --timeout TIMEOUT
                            Specifies the timeout for sniffer operation
    -f FILE, --file FILE  Specifies the filename for sniffer's pcap file
    -d, --debug           Displays debugging information

> `-la` or `--listen_addr` is a IPv4 address of listened network interface.
> If host is in `192.168.1.0/24` local network and has `192.168.1.2` IP address.
> If necessary, receive ICMP messages from this network, for which you need to specify the `-la` value `192.168.1.2`.

If an ICMP tunnel is found, displays warning:
    
    [H:M:S.f] Possible tunnel detected: A.B.C.D:X --> D.B.C.A

else displays information:
    
    [H:M:S.f] A.B.C.D --> D.B.C.A


### Create test ICMP tunnel with echo client and echo server

Client:

    python client.py -h
    usage: client.py [-h] [-pid PROCESS_ID] [-lid LISTEN_ID] [-la LISTEN_ADDR] [-c COEFF] [-t TIMEOUT] [-dr] [-di] [-df] [-f FILE]
                    [-sb SIZE_BLOCK_FILE] [-d]
                    remote_addr

    ICMP-tunneling: client script

    positional arguments:
    remote_addr           Specifies the address server

    options:
    -h, --help            show this help message and exit
    -pid PROCESS_ID, --process_id PROCESS_ID
                            Specifies the connection icmp id for client
    -lid LISTEN_ID, --listen_id LISTEN_ID
                            Specifies the connection icmp id for server
    -la LISTEN_ADDR, --listen_addr LISTEN_ADDR
                            Specifies the interface's address that listen server
    -c COEFF, --coeff COEFF
                            Specifies the one of scrambler coefficients
    -t TIMEOUT, --timeout TIMEOUT
                            Specifies the timeout for server operation
    -dr, --data_rand      Specifies the mode random generating data
    -di, --data_inp       Specifies the mode input generating data
    -df, --data_file      Specifies the mode file generating data
    -f FILE, --file FILE  Specifies the filename for mode file generating data
    -sb SIZE_BLOCK_FILE, --size_block_file SIZE_BLOCK_FILE
                            Specifies the size for block reading file for mode file generating data
    -d, --debug           Displays debugging information

Server:

    python server.py -h
    usage: server.py [-h] [-pid PROCESS_ID] [-lid LISTEN_ID] [-la LISTEN_ADDR] [-c COEFF] [-t TIMEOUT] [-d]

    ICMP-tunneling: server script

    options:
    -h, --help            show this help message and exit
    -pid PROCESS_ID, --process_id PROCESS_ID
                            Specifies the connection icmp id for server
    -lid LISTEN_ID, --listen_id LISTEN_ID
                            Specifies the connection icmp id for client
    -la LISTEN_ADDR, --listen_addr LISTEN_ADDR
                            Specifies the interface's address that listen server
    -c COEFF, --coeff COEFF
                            Specifies the one of scrambler coefficients
    -t TIMEOUT, --timeout TIMEOUT
                            Specifies the timeout for server operation
    -d, --debug           Displays debugging information

Open new terminal and run sniffer:
```
python sniffer.py -la 127.0.0.1
```

Open new terminal and run server:
```
python server.py -la 127.0.0.1
```

Open new terminal and run client:
```
python client.py 127.0.0.1 -la 127.0.0.1 -di
```

Enter different data to the client console.

> To get debugging information about types of messages sent, specify a flag `-d`.

![Echo ICMP Client](https://user-images.githubusercontent.com/39258883/216111506-c8d2f94b-e656-4507-b32a-d0486be2518f.gif)

![Echo ICMP Server](https://user-images.githubusercontent.com/39258883/216111516-0a53f380-e963-42b7-883b-1fdad1c45661.gif)

![Sniffer](https://user-images.githubusercontent.com/39258883/216111518-3bbd30f6-e483-4427-9b70-10f9edc1885e.gif)

## License

MIT. See [LICENSE](LICENSE).