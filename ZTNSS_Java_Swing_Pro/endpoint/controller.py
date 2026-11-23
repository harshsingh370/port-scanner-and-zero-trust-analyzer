#!/usr/bin/env python3
"""TLS-only ZTNSS controller. Local/LAN educational deployment; no public exposure."""
import argparse, hashlib, hmac, json, os, secrets, sqlite3, ssl, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DB=Path(os.environ.get('ZTNSS_DB','ztnss.db'))
ENROLL=os.environ.get('ZTNSS_ENROLLMENT_SECRET','')
VIEWER=os.environ.get('ZTNSS_VIEWER_TOKEN','')
def now(): return datetime.now(timezone.utc).isoformat()
def connect():
    c=sqlite3.connect(DB,timeout=10)
    c.execute('PRAGMA journal_mode=WAL')
    return c
def setup():
    with connect() as c:
        c.execute('CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY, hostname TEXT, tokenhash TEXT, enrolled TEXT, last_seen TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, device TEXT, received TEXT, source_ip TEXT, report TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS nonces(device TEXT, nonce TEXT, timestamp INTEGER, PRIMARY KEY(device,nonce))')
        c.execute('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, timestamp TEXT, device TEXT, source_ip TEXT, action TEXT, detail TEXT)')
def audit(c, device, ip, action, detail):
    c.execute('INSERT INTO events(timestamp,device,source_ip,action,detail) VALUES(?,?,?,?,?)',(now(),device,ip,action,detail))
class Handler(BaseHTTPRequestHandler):
    def send(self, code, payload):
        b=json.dumps(payload,ensure_ascii=False).encode()
        self.send_response(code); self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def read_json(self):
        n=int(self.headers.get('Content-Length','0'))
        if not 0<n<=250000: raise ValueError('Invalid report size')
        body=self.rfile.read(n)
        return body,json.loads(body)
    def authorized_viewer(self):
        value=self.headers.get('Authorization','').removeprefix('Bearer ').strip()
        return bool(VIEWER) and hmac.compare_digest(value,VIEWER)
    def do_GET(self):
        if self.path=='/health': return self.send(200,{'status':'ok','transport':'TLS'})
        if self.path not in ('/api/devices','/api/audit'): return self.send(404,{'error':'not found'})
        if not self.authorized_viewer(): return self.send(401,{'error':'viewer authentication required'})
        with connect() as c:
            if self.path=='/api/devices':
                rows=c.execute('SELECT id,hostname,enrolled,last_seen FROM devices ORDER BY hostname').fetchall()
                result=[]
                for device,hostname,enrolled,last_seen in rows:
                    latest=c.execute('SELECT received,source_ip,report FROM reports WHERE device=? ORDER BY id DESC LIMIT 1',(device,)).fetchone()
                    result.append({'device_id':device,'hostname':hostname,'enrolled':enrolled,'last_seen':last_seen,
                      'latest_report':json.loads(latest[2]) if latest else None,'source_ip':latest[1] if latest else None})
                return self.send(200,{'devices':result})
            rows=c.execute('SELECT timestamp,device,source_ip,action,detail FROM events ORDER BY id DESC LIMIT 200').fetchall()
            return self.send(200,{'events':[dict(zip(('timestamp','device','source_ip','action','detail'),r)) for r in rows]})
    def do_POST(self):
        ip=self.client_address[0]
        try: body,data=self.read_json()
        except (ValueError,UnicodeDecodeError,json.JSONDecodeError): return self.send(400,{'error':'invalid JSON or size'})
        if self.path=='/api/enroll':
            secret=self.headers.get('X-Enrollment-Secret','')
            if not ENROLL or not hmac.compare_digest(secret,ENROLL): return self.send(401,{'error':'enrollment denied'})
            device=str(data.get('device_id',''))
            hostname=str(data.get('hostname',''))
            if not (8<=len(device)<=128 and 1<=len(hostname)<=255): return self.send(400,{'error':'invalid device'})
            token=secrets.token_urlsafe(48)
            with connect() as c:
                c.execute('INSERT OR REPLACE INTO devices(id,hostname,tokenhash,enrolled,last_seen) VALUES(?,?,?,?,?)',
                          (device,hostname,hashlib.sha256(token.encode()).hexdigest(),now(),None))
                audit(c,device,ip,'ENROLL','Device enrolled; previous token invalidated')
            return self.send(200,{'device_id':device,'token':token})
        if self.path!='/api/report': return self.send(404,{'error':'not found'})
        token=self.headers.get('Authorization','').removeprefix('Bearer ').strip()
        nonce=self.headers.get('X-ZTNSS-Nonce',''); ts=self.headers.get('X-ZTNSS-Time','')
        sig=self.headers.get('X-ZTNSS-Signature','')
        try: valid_time=abs(int(time.time())-int(ts))<=300
        except ValueError: valid_time=False
        if not (token and 12<=len(nonce)<=128 and valid_time and len(sig)==64):return self.send(401,{'error':'missing/expired authentication'})
        expected=hmac.new(token.encode(),ts.encode()+b'\n'+nonce.encode()+b'\n'+body,hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,expected):return self.send(401,{'error':'signature invalid'})
        device=str(data.get('device_id',''))
        with connect() as c:
            row=c.execute('SELECT tokenhash FROM devices WHERE id=?',(device,)).fetchone()
            if not row or not hmac.compare_digest(row[0],hashlib.sha256(token.encode()).hexdigest()):return self.send(401,{'error':'unknown device'})
            try:c.execute('INSERT INTO nonces(device,nonce,timestamp) VALUES(?,?,?)',(device,nonce,int(ts)))
            except sqlite3.IntegrityError:return self.send(409,{'error':'replay detected'})
            c.execute('INSERT INTO reports(device,received,source_ip,report) VALUES(?,?,?,?)',(device,now(),ip,body.decode()))
            c.execute('UPDATE devices SET last_seen=? WHERE id=?',(now(),device))
            audit(c,device,ip,'REPORT_ACCEPTED','Endpoint posture evidence received')
            c.execute('DELETE FROM nonces WHERE timestamp<?',(int(time.time())-86400,))
        return self.send(200,{'accepted':True,'device_id':device})
    def log_message(self,*args): pass

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--bind',default='127.0.0.1');p.add_argument('--port',type=int,default=8443)
    p.add_argument('--cert',required=True);p.add_argument('--key',required=True)
    a=p.parse_args()
    if not ENROLL or not VIEWER: raise SystemExit('Set ZTNSS_ENROLLMENT_SECRET and ZTNSS_VIEWER_TOKEN to independent strong random secrets')
    setup();server=ThreadingHTTPServer((a.bind,a.port),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(a.cert,a.key);server.socket=ctx.wrap_socket(server.socket,server_side=True)
    print('ZTNSS controller listening on https://%s:%d'%(a.bind,a.port));server.serve_forever()
if __name__=='__main__':main()
