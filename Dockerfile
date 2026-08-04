FROM python:3.11-slim 
# Встановлюємо системні утиліти для роботи Scapy з мережею та iptables 
RUN apt-get update && apt-get install -y \ 
tcpdump \ 
libpcap-dev \ 
iptables \ 
sudo \ && rm -rf 
/var/lib/apt/lists/* 
WORKDIR /app 
COPY requirements.txt . 
RUN pip install --no-cache-dir -r requirements.txt 
COPY . . 
CMD ["python", "ids.py"]
