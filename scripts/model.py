import pandas as pd
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from kafka import KafkaProducer
import json
import psycopg2
import logging
import os
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Initialize Elasticsearch client
es = Elasticsearch(['http://elasticsearch:9200'])

# Initialize Kafka producer
producer = KafkaProducer(bootstrap_servers='broker:29092', value_serializer=lambda v: json.dumps(v).encode('utf-8'))

# Database connection
conn = psycopg2.connect(
    host='postgres',
    database='network_db',
    user='postgres',
    password='postgres'
)
cursor = conn.cursor()

# Function to fetch data from Elasticsearch
def fetch_data_from_elasticsearch(index_pattern):
    s = Search(using=es, index=index_pattern).query("match_all")
    response = s.scan()
    data = []
    for hit in response:
        data.append(hit.to_dict())
    return pd.DataFrame(data)

# Function to preprocess data
def preprocess_data(df):
    # Drop any rows with missing values
    df = df.dropna()
    
    # Select relevant features
    features = [
        '[network][source][ip]',
        '[network][destination][ip]',
        '[network][source][port]',
        '[network][destination][port]',
        '[network][icmp][type]',
        '[network][icmp][code]',
        '[network][bytes_transmitted]'
    ]
    return df[features]

# Load and preprocess data
df = fetch_data_from_elasticsearch('network-packets-*')
df = preprocess_data(df)

# Standardize the data for clustering
scaler = StandardScaler()
df_scaled = scaler.fit_transform(df)

# Train an Isolation Forest model for anomaly detection
anomaly_model = IsolationForest(contamination=0.01)
anomaly_model.fit(df_scaled)

# Function to detect anomalies
def detect_anomalies(data):
    anomaly_score = anomaly_model.predict(data)
    return anomaly_score

# Extended behavioral analysis and threat prediction
def analyze_behavior_and_predict_threats(df):
    # Standardize the data
    df_scaled = scaler.transform(df)
    
    # Clustering using DBSCAN for behavior analysis
    clustering_model = DBSCAN(eps=0.5, min_samples=5)
    clusters = clustering_model.fit_predict(df_scaled)
    
    # Labeling the clusters for behavior analysis
    df['cluster'] = clusters
    
    # Train a RandomForestClassifier for threat prediction
    threat_model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    # For simplicity, assuming clusters with label -1 (noise) are anomalies
    df['threat'] = df['cluster'].apply(lambda x: 1 if x == -1 else 0)
    
    # Features and target for threat prediction
    features = df.drop(columns=['cluster', 'threat'])
    target = df['threat']
    
    threat_model.fit(features, target)
    threat_prediction = threat_model.predict(df)
    
    return threat_prediction

# Function to block IP address using iptables
def block_ip(ip_address):
    try:
        os.system(f"sudo iptables -A INPUT -s {ip_address} -j DROP")
        logger.info(f"Blocked IP address: {ip_address}")
    except Exception as e:
        logger.error(f"Failed to block IP address {ip_address}: {e}")

# Function to monitor bandwidth and prevent overload
def monitor_bandwidth(df):
    bandwidth_threshold = 1000000  # Example threshold in bytes
    df['total_bytes'] = df.groupby('[network][source][ip]')['[network][bytes_transmitted]'].transform('sum')
    
    for index, row in df.iterrows():
        if row['total_bytes'] > bandwidth_threshold:
            block_ip(row['[network][source][ip]'])
            logger.warning(f"IP {row['[network][source][ip]']} blocked due to bandwidth abuse")

# Function to process and analyze new data
def process_new_data(new_data):
    df_new = preprocess_data(pd.DataFrame([new_data]))
    df_new_scaled = scaler.transform(df_new)
    anomaly_score = detect_anomalies(df_new_scaled)
    
    # Analyze behavior and predict threats
    threat_prediction = analyze_behavior_and_predict_threats(df_new)

    if anomaly_score == -1:  # -1 indicates anomaly
        new_data['anomaly'] = True
        new_data['threat_prediction'] = 'Potential Threat' if threat_prediction[0] == 1 else 'No Threat'
        
        # Send anomaly data to Kafka for SIEM
        producer.send('anomalies', value=new_data)
        
        # Insert anomaly data into PostgreSQL
        cursor.execute("""
            INSERT INTO anomalies (src_ip, dst_ip, proto, length, anomaly, threat_prediction, timestamp) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (new_data['[network][source][ip]'], new_data['[network][destination][ip]'], new_data['network_protocol'], new_data['[network][bytes_transmitted]'], new_data['anomaly'], new_data['threat_prediction'], datetime.now()))
        conn.commit()
        
        # Block the source IP of the anomaly
        block_ip(new_data['[network][source][ip]'])
    else:
        new_data['anomaly'] = False
        new_data['threat_prediction'] = 'No Threat'

    logger.info(f"Processed data: {new_data}")

# Example of processing new data and monitoring bandwidth
for index, row in df.iterrows():
    process_new_data(row.to_dict())
monitor_bandwidth(df)

# Close database connection
cursor.close()
conn.close()
