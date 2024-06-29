from scapy.all import sniff, IP, TCP, UDP, ICMP
from kafka import KafkaProducer
import json
import logging
import sys
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Initialize Kafka producer
try:
    producer = KafkaProducer(bootstrap_servers='broker:29092', value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    logger.info("Kafka producer initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Kafka producer: {e}")
    sys.exit(1)

# Data structures for traffic analysis
traffic_stats = {
    'total_packets': 0,
    'total_bytes': 0,
    'protocols': {}
}

flow_stats = {}

def update_traffic_stats(protocol, packet_length):
    if protocol not in traffic_stats['protocols']:
        traffic_stats['protocols'][protocol] = {'packets': 0, 'bytes': 0}
    traffic_stats['protocols'][protocol]['packets'] += 1
    traffic_stats['protocols'][protocol]['bytes'] += packet_length

def update_flow_stats(src_ip, dst_ip, transport_protocol, packet_length):
    flow_key = (src_ip, dst_ip)
    if flow_key not in flow_stats:
        flow_stats[flow_key] = {
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': {}
        }
    if transport_protocol not in flow_stats[flow_key]['protocols']:
        flow_stats[flow_key]['protocols'][transport_protocol] = {'packets': 0, 'bytes': 0}
    flow_stats[flow_key]['total_packets'] += 1
    flow_stats[flow_key]['total_bytes'] += packet_length
    flow_stats[flow_key]['protocols'][transport_protocol]['packets'] += 1
    flow_stats[flow_key]['protocols'][transport_protocol]['bytes'] += packet_length

def packet_callback(packet):
    try:
        if IP in packet:
            # Basic packet details
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'packet_id': packet[IP].id if 'id' in packet[IP].fields else None,
                'event_type': 'packet_capture',
                'rating': {
                    'priority': 'medium',  
                    'severity': 'low',
                    'impact': 'unknown',
                    'confidence': 'unknown'
                },
                'network_protocol': packet[IP].proto,
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'transport_protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'ICMP' if ICMP in packet else 'Unknown',
                'application_protocol': None,  
                'src_port': packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else None,
                'dst_port': packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None,
                'icmp_type': packet[ICMP].type if ICMP in packet else None,
                'icmp_code': packet[ICMP].code if ICMP in packet else None,
                'bytes_transmitted': len(packet),
                'payload': str(bytes(packet[IP].payload)),  
                'state_info': None  
            }

            # Update traffic stats
            traffic_stats['total_packets'] += 1
            traffic_stats['total_bytes'] += len(packet)
            update_traffic_stats(packet_data['network_protocol'], len(packet))

            # Update flow stats
            update_flow_stats(packet_data['src_ip'], packet_data['dst_ip'], packet_data['transport_protocol'], len(packet))

            # Log traffic analysis stats periodically
            if traffic_stats['total_packets'] % 100 == 0:
                logger.info(f"Traffic Stats: {traffic_stats}")
                logger.info(f"Flow Stats: {flow_stats}")

            # Send packet data to Kafka
            producer.send('network-packets', value=packet_data)
            logger.info(f"Packet captured: {packet_data}")

    except Exception as e:
        logger.error(f"Error processing packet: {e}")

print("Starting packet capture...")
try:
    sniff(prn=packet_callback, filter="ip", store=0)
except Exception as e:
    logger.error(f"Error starting packet capture: {e}")
