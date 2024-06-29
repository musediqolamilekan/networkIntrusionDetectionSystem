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
- **custom images for packet capture, machine learning, and alerting**