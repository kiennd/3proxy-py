'''
    apt update && apt install -y \
    git curl build-essential net-tools \
    wget unzip make gcc \
    python3 python3-pip net-tools

    cd ~
    git clone https://github.com/z3APA3A/3proxy.git
    cd 3proxy
    make -f Makefile.Linux
    mkdir -p /root/3proxy/bin
    cp src/3proxy /root/3proxy/bin/
    pip3 install flask netifaces
    sudo ufw disable
    curl -o /root/3proxy/proxy.py http://toolmmo.pro:92/files/vps_ipv6.py
    chmod +x /root/3proxy/proxy.py

    sudo nohup python3 /root/3proxy/proxy.py

'''
# 51*100+100*50+37*500+110*200
# sử dung nohup để chạy dưới nền
# tắt firewall: sudo ufw disable
#kiểm tra 3proxy đang chạy: ps aux | grep 3proxy
#sửa file: nano /root/3proxy/proxy.py
#run file: sudo python3 /root/3proxy/proxy.py
import os

import random
import subprocess
from flask import Flask, request, jsonify
import netifaces
import socket
import string

app = Flask(__name__)

BASE_IPv4 = "103.77.241.181"
IPV6_PREFIX = "2401:3660:0:c10c:"  # ⚠️ Thay bằng prefix IPv6 thực tế
NET_INTERFACE = "eth0"

CONFIG_PATH = "/root/3proxy/bin/3proxy.cfg"
API_KEY = os.environ.get("API_KEY", "2222")
PROXY_USER = os.environ.get("PROXY_USER", "PROXY_USER")
PROXY_PASS = os.environ.get("PROXY_PASS", "PROXY_PASS")
ENABLE_AUTH = os.environ.get("ENABLE_AUTH", "true").lower() in ("1","true","yes","on")
FLASK_HOST = os.environ.get("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.environ.get("FLASK_PORT", "5555"))

def is_auth_enabled():
    env_val = os.environ.get("ENABLE_AUTH")
    if env_val is not None:
        return env_val.lower() in ("1", "true", "yes", "on")
    return bool(os.environ.get("PROXY_USER")) and bool(os.environ.get("PROXY_PASS"))

running_proxies = {}  # {port: ipv6}


import time
import netifaces
import ipaddress
def reset_ipv6(interface="eth0"):
    cmds = [
        # ["sudo", "ip", "-6", "addr", "flush", "dev", interface],
        # ["sudo", "ip", "link", "set", "dev", interface, "down"],
        # ["sudo", "ip", "link", "set", "dev", interface, "up"],
        # ["sudo", "systemctl", "restart", "systemd-networkd"],
        # ["sudo", "dhclient", "-6", interface]
    ]

    for cmd in cmds:
        print(f"Running: {' '.join(cmd)}")
        subprocess.run(cmd)


def is_public_ipv4(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4 and not (ip_obj.is_loopback or ip_obj.is_link_local
        )
    except:
        return False

def is_global_ipv6(ip):
    try:
        ip_obj = ipaddress.ip_address(ip.split('%')[0])
        return ip_obj.version == 6 and ip_obj.is_global
    except:
        return False

def get_net_interface2():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)

        ipv4_list = addrs.get(netifaces.AF_INET, [])
        ipv6_list = addrs.get(netifaces.AF_INET6, [])

        ipv4 = next((item['addr'] for item in ipv4_list if is_public_ipv4(item['addr'])), None)
        ipv6 = next((item['addr'].split('%')[0] for item in ipv6_list if is_global_ipv6(item['addr'])), None)

        if ipv4 and ipv6:
            ipv6_prefix = ':'.join(ipv6.split(':')[:4]) + ':'
            return iface, ipv4, ipv6_prefix

    return None, None, None
def is_valid_ipv4(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4 and not ip_obj.is_loopback
    except:
        return False
    

import requests

def get_ipv6_prefix_64():
    solanloi = 0
    while True:
        try:
            if solanloi > 3:
                result = subprocess.run(
                    ["sudo", "reboot"],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
            # Gửi yêu cầu để lấy IPv6 từ dịch vụ
            response = requests.get("https://ipv6.icanhazip.com", timeout=5)
            response.raise_for_status()
            
            # Lấy địa chỉ IPv6 và làm sạch
            ipv6 = response.text.strip()
            
            # Cắt ra 4 block đầu tiên làm prefix /64
            blocks = ipv6.split(":")
            prefix = ":".join(blocks[:4]) + ":"
            
            return prefix
        except Exception as e:
            solanloi = solanloi + 1
            pass




def is_valid_ipv6(ip):
    try:
        # Tách bỏ phần %interface nếu có (ví dụ: fe80::1%ens33 → fe80::1)
        ip_clean = ip.split('%')[0]
        ip_obj = ipaddress.ip_address(ip_clean)
        return ip_obj.version == 6
    except:
        return False

def get_net_interface():
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)

        ipv4_list = addrs.get(netifaces.AF_INET, [])
        ipv6_list = addrs.get(netifaces.AF_INET6, [])

        # In địa chỉ để debug
        print(f"\n[+] Interface: {iface}")
        print("IPv4 List:", [a['addr'] for a in ipv4_list])
        print("IPv6 List:", [a['addr'] for a in ipv6_list])

        ipv4 = next((item['addr'] for item in ipv4_list if is_valid_ipv4(item['addr'])), None)
        ipv6 = next((item['addr'].split('%')[0] for item in ipv6_list if is_valid_ipv6(item['addr'])), None)

        if ipv4 and ipv6:
            ipv6_prefix = ':'.join(ipv6.split(':')[:4]) + ':'
            return iface, ipv4, ipv6_prefix

    return None, None, None


NET_INTERFACE, BASE_IPv4, IPV6_PREFIX = get_net_interface() # tự động lấy interface, IPv4 và IPv6 prefix
reset_ipv6(NET_INTERFACE)
print(f"Using interface: {NET_INTERFACE}, IPv4: {BASE_IPv4}, IPv6 prefix: {IPV6_PREFIX}")
IPV6_PREFIX = get_ipv6_prefix_64()
def generate_ipv6(prefix):
    suffix = ":".join('%x' % random.randint(0, 0xffff) for _ in range(4))
    return f"{prefix}{suffix}"

def assign_ipv6(ipv6):
    os.system(f"sysctl -w net.ipv6.conf.{NET_INTERFACE}.accept_dad=0")
    os.system(f"ip -6 addr add {ipv6}/64 dev {NET_INTERFACE}")

def remove_ipv6(ipv6):
    
        os.system(f"ip -6 addr del {ipv6}/64 dev {NET_INTERFACE}")
    
def remove_ipv6_port(port):
    ipv6 = read_file(f"/root/3proxy/bin/3proxy_{port}_log.txt")
    if ipv6:
        try:
            remove_ipv6(ipv6)
        except Exception as e:
            print(f"Delete ipv6 error {port} {ipv6}")
            pass
def kill_proxy(port):
    cmd = f"pkill -f '3proxy_{port}.cfg' || true"
    os.system(cmd)

def write_config(port, PROXY_USER, PROXY_PASS, ipv6):
    if is_auth_enabled():
        config = f"""
flush
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
users {PROXY_USER}:CL:{PROXY_PASS}
auth strong
allow {PROXY_USER}
allow *
socks -6 -n -a -p{port} -i{BASE_IPv4} -e{ipv6}
"""
    else:
        config = f"""
flush
nscache 65536
timeouts 1 5 30 60 180 1800 15 60
auth none
allow *
socks -6 -n -p{port} -i{BASE_IPv4} -e{ipv6}
"""
    #proxy -6 -n -a -p{port} -i{BASE_IPv4} -e{ipv6}
    conf_file = f"/root/3proxy/bin/3proxy_{port}.cfg"
    with open(conf_file, "w") as f:
        f.write(config)
    write_file(f"/root/3proxy/bin/3proxy_{port}_log.txt", ipv6)
    return conf_file

def write_file(path, data):
    with open(path, "w") as f:
        f.write(data)

def read_file(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except:
        return ""

import time
def start_proxy(port, PROXY_USER, PROXY_PASS , ipv6):
    time.sleep(2)
    conf_file = write_config(port, PROXY_USER, PROXY_PASS, ipv6)    
    subprocess.Popen(["/root/3proxy/bin/3proxy", conf_file])
    
@app.route('/closeport/')
def close_port():
    port = request.args.get("port", type=int)
    apikey = request.args.get("apikey", type=str)
    if not port:
        return jsonify({"error": "Missing port"}), 400
    if not apikey or apikey != API_KEY:
        return jsonify({"error": "Missing apikey: " + str(apikey)}), 400        
    kill_proxy(port)    
    remove_ipv6_port(port)
    return "close_ok"

# Credentials are configured via environment variables above
# PROXY_USER and PROXY_PASS default to placeholders when not provided


@app.route('/changeipv6/')
def change_proxy():
    port = request.args.get("port", type=int)
    apikey = request.args.get("apikey", type=str)
    if not port:
        return jsonify({"error": "Missing port"}), 400
    if not apikey or apikey != API_KEY: 
        return jsonify({"error": "Missing apikey: " + str(apikey)}), 400    

    kill_proxy(port)
    
    remove_ipv6_port(port)

    # Tạo mới
    ipv6 = generate_ipv6(IPV6_PREFIX)
    print(f"Generated new IPv6: {ipv6}")
    assign_ipv6(ipv6)
    start_proxy(port, PROXY_USER,PROXY_PASS, ipv6)
    if is_auth_enabled():
        return f"socks5://{BASE_IPv4}:{port}:{PROXY_USER}:{PROXY_PASS}|{ipv6}"
    else:
        return f"socks5://{BASE_IPv4}:{port}|{ipv6}"

@app.route('/getipv6/')
def getipv6():
    port = request.args.get("port", type=int)
    apikey = request.args.get("apikey", type=str)
    if not port:
        return jsonify({"error": "Missing port"}), 400
    if not apikey or apikey != API_KEY: 
        return jsonify({"error": "Missing apikey: " + str(apikey)}), 400    
    ipv6 = read_file(f"/root/3proxy/bin/3proxy_{port}_log.txt")    
    print(f"is_auth_enabled: {is_auth_enabled()}")
    if is_auth_enabled():
        return f"socks5://{BASE_IPv4}:{port}:{PROXY_USER}:{PROXY_PASS}|{ipv6}"
    else:
        return f"socks5://{BASE_IPv4}:{port}|{ipv6}"

if __name__ == '__main__':
    app.run(host=FLASK_HOST, port=FLASK_PORT)
