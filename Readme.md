# Network Intrusion Detection System (NIDS)

## Overview
This project involves setting up a Network Intrusion Detection System (NIDS) using machine learning, network traffic analysis, and SIEM tools. The system captures network packets, processes them, and identifies anomalies to alert administrators.

## Tech Stack
- **Docker**: Containerization
- **Kafka**: Distributed streaming platform
- **Elasticsearch**: Search and analytics engine
- **Kibana**: Visualization
- **Logstash**: Data processing pipeline
- **Python**: Packet capture and machine learning
- **Debezium**: Change data capture

## Docker Images
- **confluentinc/cp-zookeeper:7.4.0**
- **confluentinc/cp-kafka:7.4.0**
- **confluentinc/cp-kafka-connect:7.4.0**
- **confluentinc/cp-enterprise-control-center:7.4.0**
- **debezium/connect:latest**
- **debezium/debezium-ui:latest**
- **postgres:latest**
- **docker.elastic.co/elasticsearch/elasticsearch:7.10.0**
- **docker.elastic.co/kibana/kibana:7.10.0**
- **docker.elastic.co/logstash/logstash:7.10.0**
- **docker.elastic.co/beats/filebeat:7.10.0**
- **Custom images for packet capture, machine learning, and alerting**

## Components

### 1. Packet Capture
- **Description**: Captures network packets and extracts features.
- **Technology**: Scapy for packet capture, Python for feature extraction.

### 2. Machine Learning
- **Description**: Detects anomalies using Isolation Forest and RandomForestClassifier.
- **Technology**: scikit-learn, pandas.

### 3. Kafka
- **Description**: Streams packet data to the processing pipeline.
- **Technology**: Kafka for distributed streaming.

### 4. Data Processing Pipeline
- **Description**: Processes and stores data for further analysis.
- **Technology**: Logstash for data ingestion, Elasticsearch for storage.

### 5. SIEM and Visualization
- **Description**: Analyzes and visualizes network traffic and anomalies.
- **Technology**: Kibana for dashboards, Elasticsearch for analytics.

### 6. Alerting
- **Description**: Sends alerts on detecting anomalies.
- **Technology**: Kafka consumer for alerting, SMTP for email notifications.

## Setup Instructions

1. **Clone the repository:**
    ```bash
    git clone https://github.com/musediqolamilekan/networkIntrusionDetectionSystem.git
    ```

2. **Navigate to the project directory:**
    ```bash
    cd networkIntrusionDetectionSystem
    ```

3. **Run Docker Compose to spin up:**
    ```bash
    docker-compose up
    ```