#!/usr/bin/env python3
import os
import platform
import requests
from threading import Thread
from queue import Queue

def run(queue):
    while not queue.empty():
        try:
            line = queue.get_nowait()
            if 'https://' in line:
                url = line
            else:
                url = 'https://' + line
            osa = platform.system()
            if osa == "Linux":
                os.system('timeout 240s python3 ex.py ' + url)
            else:os.system('ex.py ' + url)
            queue.task_done()
        except KeyboardInterrupt:
            print('[+] Have fun day ;)')
            exit()

def main():
    file = open('iplist.txt').read().splitlines()
    file = list(dict.fromkeys(file))
    queue = Queue()
    for line in file:
        queue.put(line.strip())
    for i in range(20):
        thread = Thread(target=run, args=(queue,))
        thread.daemon = True
        thread.start()
    queue.join()

if __name__ == '__main__':
    try:
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
        main()
    except KeyboardInterrupt:
        exit(0)