from scapy.all import sniff, IP, TCP, UDP, ICMP
from kafka import KafkaProducer
import json
import logging
import sys
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

try:
    producer = KafkaProducer(bootstrap_servers='broker:29092', value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    logger.info("Kafka producer initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Kafka producer: {e}")
    sys.exit(1)

# Data structures for traffic analysis
traffic_stats = defaultdict(lambda: defaultdict(int))
flow_stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

def packet_callback(packet):
    try:
        if IP in packet:
            # Basic packet details
            packet_data = {
                'timestamp': datetime.now().isoformat(),
                'packet_id': packet.id if 'id' in packet else None,
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
            traffic_stats[packet_data['network_protocol']]['packets'] += 1
            traffic_stats[packet_data['network_protocol']]['bytes'] += len(packet)

            # Update flow stats
            flow_key = (packet[IP].src, packet[IP].dst)
            flow_stats[flow_key]['total_packets'] += 1
            flow_stats[flow_key]['total_bytes'] += len(packet)
            flow_stats[flow_key][packet_data['transport_protocol']]['packets'] += 1
            flow_stats[flow_key][packet_data['transport_protocol']]['bytes'] += len(packet)

            # Log traffic analysis stats periodically
            if traffic_stats['total_packets'] % 100 == 0:
                logger.info(f"Traffic Stats: {dict(traffic_stats)}")
                logger.info(f"Flow Stats: {dict(flow_stats)}")

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
