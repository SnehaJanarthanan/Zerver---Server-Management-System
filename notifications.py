import psutil
import pymongo
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from telesign.messaging import MessagingClient
import os

mongo_client = pymongo.MongoClient("mongodb+srv://test:test@sanenomore.mteelpf.mongodb.net/?retryWrites=true&w=majority")
def sendemail(subject, body, to_email):
    from_email = '727721eucs169@skcet.ac.in'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(from_email, 'hcga febg lxws ivij')
            message = MIMEMultipart()
            message['From'] = from_email
            message['To'] = to_email
            message['Subject'] = subject
            message.attach(MIMEText(body, 'plain'))
            server.sendmail(from_email, to_email, message.as_string())
            print("Email sent successfully")
    except Exception as e:
        print(f"Error sending email: {e}",subject, body, to_email)

def notify_dashboard(dbname, message, code):
    # Check if the database already exists
    notif_collection = mongo_client[dbname]["notifications"]
    document = {
    "message": message,
    "code": code
    }
    notif_collection.insert_one(document)
    print("Notification sent successfully")

def send_sms(message, phone_number, message_type="ARN"):
    try:
        customer_id = os.getenv('CUSTOMER_ID', '81680842-C2A9-4C2A-A099-EEE6C556D7F2')
        api_key = os.getenv('API_KEY', 'Jm38Hbmz0I6QX6MTsi+SQax1VQ38xRtAfuNHSAIxuVGjxK2oDnwIYP1qQAAfpwhKq/cq7OvnebFkCWpPysN9TA==')
        phone_number = os.getenv('PHONE_NUMBER', '919443335826')

        messaging = MessagingClient(customer_id, api_key)
        response = messaging.message(phone_number, message, message_type)

        print(f"\nResponse:\n{response.body}\n")

    except Exception as e:
        print(f"Error sending SMS: {e}")


# send_sms("you received the message", '9443335286')