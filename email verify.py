from mailersend import MailerSendClient, EmailBuilder
import mysql.connector;
connection = mysql.connector.connect(
                host="localhost",
                user="root",
                password="",
                port=3306,
                database="securegate"
            )

cursor=connection.cursor(buffered=True)  # fetch kelela data read tevhach kela pahije as kahi nahi so he vapraych

def generate_email(alert_type, data=None):
        if data is None:
            data = {}

        subject = ""
        message = ""

        if alert_type == "intrusion":
            subject = f"⚠️ Intrusion Alert - Suspicious Activity Detected"
            message = (
                f"Suspicious activity detected on your SecureGate system.\n"
                f"Source IP: {data.get('ip', 'Unknown')}\n"
                f"Detected at: {data.get('time', 'Unknown')}\n"
                f"Request Type: {data.get('protocol', 'Unknown')}\n\n"
                f"Recommended Action: Review the logs immediately."
            )

        elif alert_type == "ip_block":
            subject = f"🚫 IP Blocked - {data.get('ip', 'Unknown')}"
            message = (
                f"The following IP has been blocked due to exceeding request limits:\n"
                f"IP Address: {data.get('ip', 'Unknown')}\n"
                f"Blocked at: {data.get('time', 'Unknown')}\n"
                f"Reason: {data.get('reason', 'Too many requests')}\n\n"
                f"Check the SecureGate logs for details."
            )

        elif alert_type == "honeypot_trigger":
            subject = f"🐍 Honeypot Triggered - {data.get('ip', 'Unknown')}"
            message = (
                f"Honeypot diversion successfully triggered for IP: {data.get('ip', 'Unknown')}\n"
                f"Timestamp: {data.get('time', 'Unknown')}\n"
                f"Redirected to: {data.get('honeypot_ip', 'Unknown')}\n\n"
                f"SecureGate is now monitoring attacker behavior."
            )

        else:
            subject = "📢 SecureGate Notification"
            message = (
                f"An event has occurred in your SecureGate system.\n"
                f"Details: {data}\n"
            )

        return subject, message
def get_email(role):
    try:
        # ✅ 1. Connect to database
        connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="securegate"
        )
        cursor = connection.cursor()

        # ✅ 2. Fetch data depending on input
        if role == "sender":
            cursor.execute("SELECT email_token,sender_email FROM settings LIMIT 1")
            result = cursor.fetchone()
            cursor.close()
            connection.close()
            if result:
                # returns tuple (token, sender_email)
                return result
            else:
                print("[!] No sender email or token found in database.")
                return None

        elif role == "receiver":
            cursor.execute("SELECT email FROM settings LIMIT 1")
            result = cursor.fetchone()
            cursor.close()
            connection.close()
            if result and result[0]:
                return result[0]
            else:
                print("[!] No receiver email found in database.")
                return None

        else:
            print("[!] Invalid argument: use 'sender' or 'receiver'")
            return None

    except Exception as e:
        print(f"[!] Error fetching email information: {e}")
        return None

def send_email_alert(subject, message):
    try:
        token ,sender = get_email("sender")
        receiver = get_email("receiver") or sender  # fallback to same email if receiver not set
        sender="alerts@securegate.work.gd"
        if not token:
            print("[!] Missing MailerSend API token in database.")
            return

        # Initialize MailerSend client
        ms = MailerSendClient(api_key=token)

        # Build the email
        email = (
            EmailBuilder()
            .from_email(sender, "SecureGate Alert System")
            .to_many([{"email": receiver, "name": "Admin"}])
            .subject(subject)
            .html(f"<h3>{subject}</h3><p>{message}</p>")
            .text(message)
            .build()
        )

        # Send the email
        response = ms.emails.send(email)
        print("[+] Email sent successfully via MailerSend!")
        print("Response:", response)

    except Exception as e:
        print(f"[!] Failed to send email: {e}")
    finally:
        ms = MailerSendClient(token)

        email = (EmailBuilder()
         .from_email("alerts@test-r83ql3pq5j0gzw1j.mlsender.net", "SecureGate System")
         .to_many([{"email": "", "name": "Admin"}])
         .subject("SecureGate Alert")
         .html("<p>Suspicious activity detected!</p>")
         .text("Suspicious activity detected!")
         .build())

        esponse = ms.emails.send(email)
send_email_alert("hello","testing")