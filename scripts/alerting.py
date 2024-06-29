from kafka import KafkaConsumer
import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Initialize Kafka consumer
consumer = KafkaConsumer('anomalies', bootstrap_servers='broker:29092', value_deserializer=lambda v: json.loads(v.decode('utf-8')))

# Function to send email
def send_email(alert):
    from_addr = 'musediqolamilekan567@gmail.com'
    to_addr = 'musediqolamilekan5@gmail.com'
    subject = 'Network Anomaly Detected'
    body = f"Anomaly detected:\n\n{json.dumps(alert, indent=4)}"
    
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        with smtplib.SMTP('localhost', 1025) as server:  
            server.sendmail(from_addr, to_addr, msg.as_string())
        logger.info(f"Alert email sent to {to_addr}: {alert}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")

# Listen for messages from the 'anomalies' topic
for msg in consumer:
    alert = msg.value
    logger.info(f"Received alert: {alert}")
    send_email(alert)
