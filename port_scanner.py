#!/usr/bin/python3

################### Libraries ####################

from argparse import ArgumentParser
import csv
from time import sleep
from threading import Thread
from colorama import Fore, Style, init
from socket import *
import os
import sys
import re

##################################################


class Scanner:
    available_ports = []

    def __init__(self, host: str, ports: int, threads: int=10) -> None:
        self.host    = host
        self.ports   = ports
        self.threads = threads

    def __scan_port__(self, port) -> None:
        s = socket(AF_INET, SOCK_STREAM) # TCP/IP
        s.settimeout(3)
        err_code = s.connect_ex((self.host, port))
        if err_code == 0:
            self.available_ports.append(port)
        s.close()
    
    def scan(self) -> list:
        """

            This is the main function that implements port scanning.
            Returns sorted list, which will contain available ports on a host.
            
        """
        port = iter(ports)
        done = False
        while not done:
            threads_arr = []
            try:
                for _ in range(self.threads): # Scans ports in batches with little interval
                    port_to_scan = next(port)
                    thr = Thread(target=self.__scan_port__, 
                                args=(port_to_scan,))
                    threads_arr.append(thr)
                    thr.start()
                sleep(.5)
            except StopIteration: # Causes when iterator reached its end
                done = True
            except KeyboardInterrupt:
                print(f'{Fore.LIGHTWHITE_EX}Got process interruption\n{Fore.YELLOW}Exiting...{Style.RESET_ALL}')
                exit(-1)
            ready = False
        while not ready: # Checks threads, that are still running
            ready = True
            for x in threads_arr:
                if x.is_alive():
                    ready = False
        self.available_ports.sort()
        return self.available_ports
if __name__ == "__main__":
    init() # Colorama init
    class MyParser(ArgumentParser):
        def error(self, message):
            print(Fore.CYAN, end='')
            self.print_help()
            print(Style.RESET_ALL)
            sys.stderr.write(f'{Fore.RED}error: {message}{Style.RESET_ALL}\n')
            sys.exit(2)
    parser  = MyParser(prog='Port Scanner',
                            description='Simple port scanner')
    
    parser.add_argument('-H', '--host', 
                        required=True,
                        type=str, 
                        help=f'{Fore.LIGHTWHITE_EX}A server domain or an IP address( like www.google.com or 127.0.0.1 ){Style.RESET_ALL}{Fore.CYAN}')
    parser.add_argument('-P', '--ports', 
                        default='1-65535',
                        type=str,
                        help=f'{Fore.LIGHTWHITE_EX}Ports to scan. It can be range-like ( 1-65535 ) or a list ( 22,80,443 ){Style.RESET_ALL}{Fore.CYAN}')
    parser.add_argument('-T', '--threads',
                        type=int,
                        default=10,
                        help=f'{Fore.LIGHTWHITE_EX}Number of threads{Style.RESET_ALL}')
    args = parser.parse_args()

    host    = gethostbyname(args.host)
    
    ports_str   = args.ports

    if re.match(r'^\d+\-\d+$', ports_str):
        range_ = ports_str.split('-')
        ports = list(range(int(range_[0]), int(range_[1])+1))
    elif re.match(r'^(\d+\,)+\d+$', ports_str):
        ports = [int(i) for i in ports_str.split(',')]
    elif re.match(r'^\d+$', ports_str):
        ports = [int(ports_str)]
    else:
        print(f'{Fore.RED}Not recognized ports range or list. Must be like 1-65535 or 22,80,443\n{Fore.BLACK}You\'ve entered {ports_str}{Style.RESET_ALL}')
        exit(-1)
    
    threads = args.threads
    scanner = Scanner(host, ports=ports, threads=threads)

    available_ports = scanner.scan()

    dict_ = {}

    csv_dest = os.path.join(os.path.dirname(__file__), 'service-names-port-numbers.csv')

    with open(csv_dest, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            for port in available_ports:
                if str(port) == row['Port Number']:
                    dict_[port] = row['Service Name']
    
    print('\t\tOPEN PORTS')

    print('\n'.join(f'{Fore.GREEN}{key:>10}  |  {Fore.MAGENTA}{dict_[key]}{Style.RESET_ALL}' for key in list(dict_.keys())))