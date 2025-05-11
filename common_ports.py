"""
Common ports and services for Nexus Port Scanner
"""

# Top 100 most common TCP ports as of 2023
TOP_PORTS = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
    143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
    10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
    5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
    2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
    544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
    7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
    6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37
]

# Common services and their default ports
SERVICES = {
    # Web
    'http': 80,
    'https': 443,
    'http-alt': 8080,
    'http-proxy': 8080,
    
    # File Transfer
    'ftp': 21,
    'ftp-data': 20,
    'sftp': 22,
    'tftp': 69,
    'rsync': 873,
    
    # Email
    'smtp': 25,
    'smtps': 587,
    'pop3': 110,
    'pop3s': 995,
    'imap': 143,
    'imaps': 993,
    
    # Remote Access
    'ssh': 22,
    'telnet': 23,
    'rdp': 3389,
    'vnc': 5900,
    'x11': 6000,
    
    # Databases
    'mysql': 3306,
    'postgresql': 5432,
    'mongodb': 27017,
    'redis': 6379,
    'oracle': 1521,
    'mssql': 1433,
    
    # Web Services
    'http-alt': 8080,
    'http-alt-ssl': 8443,
    'http-admin': 8081,
    'http-mgmt': 10000,
    
    # Virtualization
    'vmware-auth': 902,
    'vmware-http': 8307,
    'vmware-https': 8308,
    'docker': 2375,
    'docker-tls': 2376,
    
    # Monitoring
    'snmp': 161,
    'snmp-trap': 162,
    'zabbix-agent': 10050,
    'zabbix-server': 10051,
    'prometheus': 9090,
    'grafana': 3000,
    
    # Messaging
    'mqtt': 1883,
    'mqtts': 8883,
    'amqp': 5672,
    'amqps': 5671,
    'stomp': 61613,
    
    # Containers & Orchestration
    'kubernetes': 6443,
    'kubelet': 10250,
    'etcd': 2379,
    'etcd-client': 2379,
    'etcd-server': 2380,
    
    # Version Control
    'git': 9418,
    'svn': 3690,
    'git-http': 80,
    'git-https': 443,
    
    # Other Common Services
    'dns': 53,
    'dhcp': 67,
    'ntp': 123,
    'ldap': 389,
    'ldaps': 636,
    'kerberos': 88,
    'kerberos-sec': 88,
    'rpcbind': 111,
    'nfs': 2049,
    'samba': 445,
    'smb': 445,
    'cifs': 445
}
