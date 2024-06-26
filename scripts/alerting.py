from kafka import KafkaConsumer
import json
import smtplib

consumer = KafkaConsumer('anomalies', bootstrap_servers='broker:29092', value_serializer=lambda v: json.dumps(v).encode('utf-8'))

def send_email(alert):
    from_addr = 'your_email@example.com'
    to_addr = 'admin@example.com'
    subject = 'Network Anomaly Detected'
    body = f"Anomaly detected: {alert}"
    
    email_message = f"Subject: {subject}\n\n{body}"
    
    with smtplib.SMTP('smtp.example.com', 587) as server:
        server.starttls()
        server.login('your_email@example.com', 'your_password')
        server.sendmail(from_addr, to_addr, email_message)

for msg in consumer:
    alert = json.loads(msg.value)
    send_email(alert)
