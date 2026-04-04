import argparse
import re
import sys
import socket
import requests
import fpdf


def main():
    parser=argparse.ArgumentParser(description="A security test for: 1. Ports 2. Headers 3. Password ")
    parser.add_argument("--host",default="", help="host to check ports")
    parser.add_argument("--url",default="", help="url to check headers")
    parser.add_argument("--password",default="", help="password to check its strength")
    args=parser.parse_args()
    host,url,password=validate_input(args.host,args.url,args.password)
    

def validate_input(host="", url="", password=""):
    if not host=="":
        domain=re.search(r"^(www\.)?[a-z][a-z0-9-]+\.[a-z0-9][\.a-z0-9]?$",host, flags=re.IGNORECASE)
        ip=re.search(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$",host)
        if domain:
            h= host
        elif ip and all(0<=int(ip.group(i))<=255 for i in range (1,5)):
            h= host
        else:
            sys.exit("Invalid Host")
    else:
        h=""
    if not url=="":
        url1=re.search(r"^(https?://)?(www\.)?[a-z][a-z0-9-]+\.[a-z0-9][\.a-z0-9]?(/\w+)?$",url, flags=re.IGNORECASE)
        if url1:
            u=url
        else:
            sys.exit("Invalid Url")
    else:
        u=""
    if not password=="":
        p=password
    else:
        p=""
    return (h,u,p)


def scan_ports(host):
    ports={
        21:"FTP",
        22:"SSH",
        23:"Telnet",
        25:"SMTP",
        53:"DNS",
        80:"HTTP",
        443:"HTTPS",
        3306:"MySQL",
        5432:"PostgreSQL",
        8080:"HTTP alternate",
        8443:"HTTPS alternate",
        27017:"MongoDB"
    }
    open_ports={}
    for port in ports:
        s=socket.socket()
        s.settimeout(1)
        result=s.connect_ex((host,port))
        if result==0:
            open_ports[port]=ports[port]
        s.close()
    return open_ports


def check_headers(url):
    headers=[
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
        "Cache-Control",
        "Cross-Origin-Opener-Policy",
        "Cross-Origin-Resource-Policy"
    ]
    response=requests.get(url)
    s=response.headers
    headers_missing=[]
    for header in headers:
        if header not in s:
            headers_missing.append(header)        
    return headers_missing


def password_strength(password):
    score=0
    if any(c.isupper() for c in password):
        score+=1
    if any(c.islower() for c in password):
        score+=1
    if any(c.isdigit() for c in password):
        score+=1
    if any(not c.isalnum() for c in password):
        score+=1
    if password[0].isalpha():
        score+=1
    if len(password)>=8:
        score+=1
    if score<=2:
        return (score,"Weak")
    elif score<=4:
        return (score,"Moderate")
    else:
        return (score,"High")
    

def generate_report():
    