1) In this folder (where server.py/client.py live), install deps:
sudo apt update
sudo apt install -y python3-minimal mininet xterm tcpdump openssl netcat-openbsd

2) Make test certificates:
# legit
   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
     -days 365 -nodes -subj "/CN=chat.local" -addext "subjectAltName=DNS:chat.local"

# evil
   openssl req -x509 -newkey rsa:2048 -keyout evil.key -out evil.crt \
     -days 365 -nodes -subj "/CN=evil.local" -addext "subjectAltName=DNS:evil.local"

3) Start Mininet with a simple 3-host topology:
sudo mn --topo single,3

4) Open terminals for client/server:
mininet> xterm h1 h2

5) Run the legit TLS server on h2:
python3 server.py --cert server.crt --key server.key --port 5443 --label SERVER

6) Run the validating client on h1:
   python3 client.py --mode validate \
     --host 10.0.0.2 --server-name chat.local \
     --cafile server.crt --port 5443
