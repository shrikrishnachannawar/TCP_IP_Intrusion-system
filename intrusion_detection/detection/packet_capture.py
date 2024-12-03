''''
from scapy.all import sniff, IP, TCP
from detection.models import intrusionLog
import joblib
import numpy as np
import djnago, os

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'intrusion_detection.settings')
django.setup()

#load the model
model=joblib.load("tcp_intrusion_model.sav")

# adding the features 
features= [
    'service', 'src_bytes', 'dst_bytes', 'count', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'protocol_type_icmp', 'flag_SF'
]

#one hot encoding service for the 
service_encoding={
    'ftp_data': 0, 'other': 1, 'private': 2, 'http': 3, 'remote_job': 4, 'name': 5,
    'netbios_ns': 6, 'eco_i': 7, 'mtp': 8, 'telnet': 9, 'finger': 10, 'domain_u': 11,
    'supdup': 12, 'uucp_path': 13, 'Z39_50': 14, 'smtp': 15, 'csnet_ns': 16, 'uucp': 17,
    'netbios_dgm': 18, 'urp_i': 19, 'auth': 20, 'domain': 21, 'ftp': 22, 'bgp': 23,
    'ldap': 24, 'ecr_i': 25, 'gopher': 26, 'vmnet': 27, 'systat': 28, 'http_443': 29,
    'efs': 30, 'whois': 31, 'imap4': 32, 'iso_tsap': 33, 'echo': 34, 'klogin': 35,
    'link': 36, 'sunrpc': 37, 'login': 38, 'kshell': 39, 'sql_net': 40, 'time': 41,
    'hostnames': 42, 'exec': 43, 'ntp_u': 44, 'discard': 45, 'nntp': 46, 'courier': 47,
    'ctf': 48, 'ssh': 49, 'daytime': 50, 'shell': 51, 'netstat': 52, 'pop_3': 53,
    'nnsp': 54, 'IRC': 55, 'pop_2': 56, 'printer': 57, 'tim_i': 58, 'pm_dump': 59,
    'red_i': 60, 'netbios_ssn': 61, 'rje': 62, 'X11': 63, 'urh_i': 64, 'http_8001': 65
}
num_service=len(service_encoding)
# one hot encodind function
def one_hot_encoding_service(service):
    one_hot= np.zeros(service_encoding)
    if service in service_encoding:
        one_hot[service_encoding[service]]=1
    return one_hot

# preapre the function form the ml model
def prepare_features(service, src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate, 
                     dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag):
    #one hot encoding service
    service_encoded=one_hot_encoding_service(service)
    
    # Convert protocol and flag into binary indicators
    protocol_icmp=1 if protocol ==1 else 0
    flag_SF=1 if flag == "SF" else 0 
    
    #combine all features 
    numaric_features = np.array([
        src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate,
        dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol_icmp, flag_SF
    ])
    return np.concatenate((service_encoded, numaric_features))

def predict_intrusion(service, src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate, 
                      dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag):
    #prepare input features
    features = prepare_features(service, src_bytes, dst_bytes, count, same_srv_rate, 
                                 diff_srv_rate, dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag)
    #reshpe for the model prediction
    features=features.reshape(1,-1)
    
    # Make prediction
    prediction = model.predict(features)
    return prediction[0] #return the predicted class 

connection_counts = {}
connections = []  # Track active connections


def extract_packet_details(packet):
    if IP in  packet:
        src_ip=packet[IP].src
        dst_ip=packet[IP].dst
        protocol=packet[IP].proto
        size=len(packet)
        service=one_hot_encoding_service(service)
        
        connection_key = (src_ip, dst_ip, protocol)
        connection_counts[connection_key] = connection_counts.get(connection_key, 0) + 1
        count = connection_counts[connection_key]
        
        # Calculate same_srv_rate and diff_srv_rate
        same_service_count = sum(1 for conn in connections if conn[1] == dst_ip)
        total_count = len(connections)
        same_srv_rate = same_service_count / total_count if total_count > 0 else 0
        diff_srv_rate = 1 - same_srv_rate
        
        # Calculate dst_host_same_srv_rate and dst_host_diff_srv_rate
        same_service_count_dst = sum(1 for conn in connections if conn[0] == dst_ip)
        total_dst_count = sum(1 for conn in connections if conn[0] == dst_ip)
        dst_host_same_srv_rate = same_service_count_dst / total_dst_count if total_dst_count > 0 else 0
        dst_host_diff_srv_rate = 1 - dst_host_same_srv_rate
        dst_bytes=len(packet[IP].payload)#Simulate for reverse traffic
        # Extract flag
        flag = "SF" if TCP in packet and packet[TCP].flags == 0x02 else "Other"

        return service, len(packet[IP].payload), dst_bytes, count, same_srv_rate, diff_srv_rate, \
               dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag, src_ip, dst_ip, size
        
    return None

def capture_packets():
    def process_packet(packet):
        details= extract_packet_details(packet)
        if details:
            service, src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate, \
            dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag, src_ip, dst_ip, size = details

            # make prediction
            prediction=predict_intrusion(service, src_bytes, dst_bytes, count, same_srv_rate, 
                                           diff_srv_rate, dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag)

            
            #save to DB 
            intrusionLog.objects.create(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=str(protocol),
                packet_size=size,
                prediction=prediction
            )
            print(f"packet Logged: {src_ip}->{dst_ip} | {prediction}")
    sniff(fliter='ip', prn=process_packet, count=0) #capture indefinaitly     
    '''
    
from scapy.all import sniff, IP, TCP, conf
import joblib
import numpy as np
import django, os, sys

# Django setup
sys.path.append('D:/TCP_IP_Intrusion system') 
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'intrusion_detection.settings')
django.setup()

from detection.models import intrusionLog


# Load the model
model = joblib.load("tcp_intrusion_model.sav")

# Define features and service encoding
features = [
    'service', 'src_bytes', 'dst_bytes', 'count', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'protocol_type_icmp', 'flag_SF'
]

service_encoding = {
    'ftp_data': 0, 'other': 1, 'private': 2, 'http': 3, 'remote_job': 4, 'name': 5,
    'netbios_ns': 6, 'eco_i': 7, 'mtp': 8, 'telnet': 9, 'finger': 10, 'domain_u': 11,
    'supdup': 12, 'uucp_path': 13, 'Z39_50': 14, 'smtp': 15, 'csnet_ns': 16, 'uucp': 17,
    'netbios_dgm': 18, 'urp_i': 19, 'auth': 20, 'domain': 21, 'ftp': 22, 'bgp': 23,
    'ldap': 24, 'ecr_i': 25, 'gopher': 26, 'vmnet': 27, 'systat': 28, 'http_443': 29,
    'efs': 30, 'whois': 31, 'imap4': 32, 'iso_tsap': 33, 'echo': 34, 'klogin': 35,
    'link': 36, 'sunrpc': 37, 'login': 38, 'kshell': 39, 'sql_net': 40, 'time': 41,
    'hostnames': 42, 'exec': 43, 'ntp_u': 44, 'discard': 45, 'nntp': 46, 'courier': 47,
    'ctf': 48, 'ssh': 49, 'daytime': 50, 'shell': 51, 'netstat': 52, 'pop_3': 53,
    'nnsp': 54, 'IRC': 55, 'pop_2': 56, 'printer': 57, 'tim_i': 58, 'pm_dump': 59,
    'red_i': 60, 'netbios_ssn': 61, 'rje': 62, 'X11': 63, 'urh_i': 64, 'http_8001': 65
}
num_service = len(service_encoding)

# One-hot encoding function
def one_hot_encoding_service(service):
    one_hot = np.zeros(num_service)
    if service in service_encoding:
        one_hot[service_encoding[service]] = 1
    return one_hot

# Prepare features for ML model
def prepare_features(service, src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate, 
                     dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag):
    # One-hot encode service
    service_encoded = one_hot_encoding_service(service)
    
    # Convert protocol and flag into binary indicators
    protocol_icmp = 1 if protocol == 1 else 0
    flag_SF = 1 if flag == "SF" else 0 
    
    # Combine all features
    numeric_features = np.array([
        src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate,
        dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol_icmp, flag_SF
    ])
    return np.concatenate((service_encoded, numeric_features))

def predict_intrusion(service, src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate, 
                      dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag):
    # Prepare input features
    features = prepare_features(service, src_bytes, dst_bytes, count, same_srv_rate, 
                                 diff_srv_rate, dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag)
    # Reshape for model prediction
    features = features.reshape(1, -1)
    
    # Make prediction
    prediction = model.predict(features)
    return prediction[0]  # Return the predicted class 

# Connection tracking
connection_counts = {}
connections = []  # Track active connections

def extract_packet_details(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        service = "http"  # Default to "http" for simplicity
        size = len(packet)
        
        connection_key = (src_ip, dst_ip, protocol)
        connection_counts[connection_key] = connection_counts.get(connection_key, 0) + 1
        count = connection_counts[connection_key]
        
        # Calculate same_srv_rate and diff_srv_rate
        same_service_count = sum(1 for conn in connections if conn[1] == dst_ip)
        total_count = len(connections)
        same_srv_rate = same_service_count / total_count if total_count > 0 else 0
        diff_srv_rate = 1 - same_srv_rate
        
        # Calculate dst_host_same_srv_rate and dst_host_diff_srv_rate
        same_service_count_dst = sum(1 for conn in connections if conn[0] == dst_ip)
        total_dst_count = sum(1 for conn in connections if conn[0] == dst_ip)
        dst_host_same_srv_rate = same_service_count_dst / total_dst_count if total_dst_count > 0 else 0
        dst_host_diff_srv_rate = 1 - dst_host_same_srv_rate
        
        # Extract flag
        flag = "SF" if TCP in packet and packet[TCP].flags == 0x02 else "Other"

        return service, len(packet[IP].payload), size, count, same_srv_rate, diff_srv_rate, \
               dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag, src_ip, dst_ip
    return None

def capture_packets():
    def process_packet(packet):
        details = extract_packet_details(packet)
        if details:
            service, src_bytes, dst_bytes, count, same_srv_rate, diff_srv_rate, \
            dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag, src_ip, dst_ip = details

            # Make prediction
            prediction = predict_intrusion(service, src_bytes, dst_bytes, count, same_srv_rate, 
                                           diff_srv_rate, dst_host_same_srv_rate, dst_host_diff_srv_rate, protocol, flag)

            # Save to DB
            try:
                intrusionLog.objects.create(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=str(protocol),
                    packet_size=dst_bytes,
                    prediction=prediction
                )
                print(f"Packet Logged: {src_ip} -> {dst_ip} | Prediction: {prediction}")
            except Exception as e:
                print(f"Failed to log packet: {e}")
                
    sniff(filter='ip', prn=process_packet, store=False)  # Capture indefinitely

if __name__ == "__main__":
    print("Starting packet capture...")
    capture_packets()
