import streamlit as st
import pandas as pd
import sqlite3
import matplotlib.pyplot as plt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sender_email = "avzoor925@gmail.com" # Testing Environment
password = "dgxl odeo mmrg jkba"
subject = "Decryption Key Delivery (Project - Network Security Topics)"

conn = sqlite3.connect("table.db")
df1 = pd.read_sql_query("SELECT * FROM users", conn)
df2 = pd.read_sql_query("SELECT * FROM statistics", conn)
cursor = conn.cursor()

df1['timestamp'] = pd.to_datetime(df1['timestamp'], dayfirst=True)

st.set_page_config(page_title="Dashboard", layout="wide")
st.title("Ransomware Simulation - Dashboard")

st.subheader("User Records")
st.dataframe(df1)

st.subheader("Statistical Records")
st.dataframe(df2)

#----------------------------------------------------------------------------------------------------#

# Sending the decryption key to the appropriate email address.

st.divider()

session_id = st.text_input("Enter the user's ID number to send them the decryption key.", placeholder="ID number")

col1, col2 = st.columns([4, 4])

with col1:
       if st.button("Send"):

              cursor.execute("""
              SELECT email_address, key FROM users
              WHERE ID = ?
              """, (session_id,))

              values = cursor.fetchone()

              if values is not None:

                     receiver_email, key = values

                     if receiver_email is not None:

                            message = MIMEMultipart()
                            message["From"] = sender_email
                            message["To"] = receiver_email
                            message["Subject"] = subject

                            body = f"Here is your decryption key: {key}"
                            message.attach(MIMEText(body, "plain"))

                            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                                   server.login(sender_email, password)
                                   server.sendmail(sender_email, receiver_email, message.as_string())

                            st.success("A decryption key has been sent to the user.")

                     else:
                            st.warning("No email was received from the user.")
              else:
                     st.warning("No user was found with this ID number.")


#----------------------------------------------------------------------------------------------------#

# Displaying graphs.

st.divider()

st.subheader("Status Distribution")

fig, ax = plt.subplots(figsize=(3, 3))
df1['status'].value_counts().plot(kind='pie', autopct='%1.1f%%', startangle=90, ax=ax, textprops={'fontsize': 6})
ax.set_ylabel("")
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#

st.subheader("Payment Attempts vs Decryption Attempts")

fig, ax = plt.subplots(figsize=(3, 3))
df2['payment_attempts'] = pd.to_numeric(df2['payment_attempts'], errors='coerce')
df2['decryption_attempts'] = pd.to_numeric(df2['decryption_attempts'], errors='coerce')
ax.bar(['Decryption Attempts', 'Payment Attempts'], 
       [df2['decryption_attempts'].sum(), df2['payment_attempts'].sum()])
ax.set_ylabel("Total Attempts", fontsize=6)
ax.set_xticklabels(ax.get_xticklabels(), fontsize=6)
ax.tick_params(axis='both', labelsize=6)
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#

st.subheader("Payment Elapsed Time Distribution")

fig, ax = plt.subplots(figsize=(3, 3))
df2['payment_elapsed_time'] = pd.to_numeric(df2['payment_elapsed_time'], errors='coerce')
df2['payment_elapsed_time'].dropna().plot(kind='hist', bins=10, ax=ax)
ax.set_xlabel("Seconds", fontsize=6)
ax.set_ylabel("Number of Users", fontsize=6)
ax.tick_params(axis='both', labelsize=6)
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#

st.subheader("Decryption Elapsed Time Distribution")

fig, ax = plt.subplots(figsize=(3, 3))
df2['decryption_elapsed_time'] = pd.to_numeric(df2['decryption_elapsed_time'], errors='coerce')
df2['decryption_elapsed_time'].dropna().plot(kind='hist', bins=10, ax=ax)
ax.set_xlabel("Seconds", fontsize=6)
ax.set_ylabel("Number of Users", fontsize=6)
ax.tick_params(axis='both', labelsize=6)
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#

st.subheader("Help Elapsed Time Distribution")

fig, ax = plt.subplots(figsize=(3, 3))
df2['help_elapsed_time'] = pd.to_numeric(df2['help_elapsed_time'], errors='coerce')
df2['help_elapsed_time'].dropna().plot(kind='hist', bins=10, ax=ax)
ax.set_xlabel("Seconds", fontsize=6)
ax.set_ylabel("Number of Users", fontsize=6)
ax.tick_params(axis='both', labelsize=6)
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#

st.subheader("First User Action Based on Elapsed Time")

time_columns = ["decryption_elapsed_time", "payment_elapsed_time", "help_elapsed_time"]
df2["first_action"] = df2[time_columns].idxmin(axis=1)
df2["first_action"] = df2["first_action"].str.replace("_elapsed_time", "")

fig, ax = plt.subplots(figsize=(3, 3))
action_counts = df2["first_action"].value_counts()
action_counts.plot(kind="pie", autopct="%1.1f%%", startangle=90, ax=ax, textprops={'fontsize': 6})
ax.set_ylabel("")
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#

st.subheader("Personal Information Submission Distribution")

fig, ax = plt.subplots(figsize=(3, 3))
df2['is_personal_information_provided'].value_counts().plot(kind='pie', autopct='%1.1f%%', startangle=90, ax=ax, textprops={'fontsize': 6})
ax.set_ylabel("")
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#

st.subheader("Window Closure Methods Distribution")

fig, ax = plt.subplots(figsize=(3, 3))
df2['window_closure_method'].value_counts().plot(kind='pie', autopct='%1.1f%%', startangle=90, ax=ax, textprops={'fontsize': 6})
ax.set_ylabel("")
st.pyplot(fig, use_container_width=False)

#----------------------------------------------------------------------------------------------------#