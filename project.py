import argparse
import re
import sys
import socket
import requests
from fpdf import FPDF


def main():
    parser=argparse.ArgumentParser(description="A security test for: 1. Ports 2. Headers 3. Password ")
    parser.add_argument("--host",default="", help="host to check ports")
    parser.add_argument("--url",default="", help="url to check headers")
    parser.add_argument("--password",default="", help="password to check its strength")
    args=parser.parse_args()
    host,url,password=validate_input(args.host,args.url,args.password)
    generate_report(host,url,password,scan_ports(host),check_headers(url),password_strength(password))
    

def validate_input(host="", url="", password=""):
    if not host=="":
        domain=re.search(r"^(www\.)?[a-z][a-z0-9-]+\.[a-z]{2,}$",host, flags=re.IGNORECASE)
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
        url1=re.search(r"^(https?://)?(www\.)?[a-z][a-z0-9-]+\.[a-z]{2,}(/\w+)?$",url, flags=re.IGNORECASE)
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
    if not host=="":
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
    else:
        return None


def check_headers(url):
    if not url=="":    
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
    else:
        return None


def password_strength(password):
    if not password=="":
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
    else:
        return None

def generate_report(host="",url="",password="", open_ports=None, missing_headers=None, pas=None):
    pdf=FPDF(orientation="P",unit="mm", format="A4")
    pdf.add_page()
    pdf.set_font("Helvetica",style="B",size=35)
    pdf.cell(w=0,text="--SECURITY CHECKS--",align="C")
    pdf.ln()
    pdf.ln()

    if host=="" and url=="" and password=="":
        pdf.set_font("Helvetica",style="",size=18)
        pdf.cell(w=0,text="NO HOST URL OR PASSWORD ENTERED FOR SECURITY CHECK",align="C")
        pdf.ln()
        pdf.ln()

    if not host=="":
        pdf.set_font("Helvetica",style="",size=18)
        pdf.cell(w=0,text=f"CHECK FOR OPEN PORTS IN {host}:-", align="L")
        pdf.ln()
        pdf.ln()
        
        if open_ports:
            pdf.cell(w=0,text="OPEN PORTS FOUND ARE:-")
            pdf.ln()
            pdf.ln()
            pdf.set_font("Helvetica",style="",size=10)
            with pdf.table() as  table:
                row=table.row()
                row.cell(text="PORT")
                row.cell(text="SERVICE")
                for port in open_ports:
                    row=table.row()
                    row.cell(text=f"{port}")
                    row.cell(text=open_ports[port])
            pdf.ln()
        else:
            pdf.cell(w=0,text="NO OPEN PORTS FOUND")
    else:
        pdf.ln()
    
    if not url=="":
        pdf.set_font("Helvetica",style="",size=18)
        pdf.cell(w=0,text=f"CHECK FOR HEADERS IN {url}:-", align="L")
        pdf.ln()
        pdf.ln()
        if missing_headers:
            pdf.cell(w=0,text="LIST OF HEADERS NOT PRESENT:-")
            pdf.ln()
            pdf.ln()
            pdf.set_font("Helvetica",style="",size=10)
            for i,header in enumerate(missing_headers):
                pdf.cell(text=f"{i+1}. {header}")
                pdf.ln()
            pdf.ln()
        else:
            pdf.cell(w=0,text="ALL HEADERS PRESENT")
            pdf.ln()
    else:
        pdf.ln()
    
    if not password=="":
        pdf.set_font("Helvetica",style="",size=18)
        pdf.cell(w=0,text=f"CHECK FOR STRENGTH OF PASSWORD:-", align="L")
        pdf.ln()
        pdf.ln()
        if pas:
            pass_score,pass_strength=pas
            pdf.set_font("Helvetica",style="",size=10)
            pdf.cell(text=f"Score: {pass_score}, Strength: {pass_strength}")
            pdf.ln()
        else:
            pdf.ln()
    else:
        pdf.ln()

    pdf.output("report.pdf")


if __name__=="__main__":
    main()