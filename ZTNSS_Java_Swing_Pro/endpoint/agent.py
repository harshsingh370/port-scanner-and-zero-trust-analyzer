#!/usr/bin/env python3
"""Explicitly enrolled, one-shot local posture agent; no remote command execution."""
import argparse, base64, ctypes, hashlib, hmac, json, os, platform, secrets, socket, subprocess, time, urllib.request
from ctypes import wintypes
from datetime import datetime, timezone
from pathlib import Path

HOME=Path.home()/'.ztnss-agent'; CONFIG=HOME/'identity.json'
def command(args,timeout=12):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=timeout,encoding='utf-8',errors='replace')
        out=(p.stdout+p.stderr).strip()[:6000]
        return {'status':'needs_review' if p.returncode==0 and out else 'unknown', 'exit_code':p.returncode,'evidence':out or 'No evidence returned'}
    except Exception as e:return {'status':'unknown','evidence':type(e).__name__+': '+str(e)}
def powershell(cmd):return command(['powershell.exe','-NoProfile','-NonInteractive','-Command',cmd])
def collect():
    system=platform.system(); checks={}
    if system=='Windows':
        checks['os_patch']=powershell("$o=Get-CimInstance Win32_OperatingSystem; $h=Get-HotFix|Sort-Object InstalledOn -Descending|Select-Object -First 1; [pscustomobject]@{OS=$o.Caption;Build=$o.BuildNumber;LastHotfix=$h.HotFixID;Date=$h.InstalledOn}|ConvertTo-Json -Compress")
        checks['antivirus']=powershell('Get-MpComputerStatus|Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated|ConvertTo-Json -Compress')
        checks['encryption']=powershell('Get-BitLockerVolume|Select-Object MountPoint,ProtectionStatus,VolumeStatus|ConvertTo-Json -Compress')
        checks['admins']=powershell('Get-LocalGroupMember -Group Administrators|Select-Object Name,ObjectClass|ConvertTo-Json -Compress')
        checks['processes']=powershell('Get-Process|Select-Object -First 80 ProcessName,Id|ConvertTo-Json -Compress')
        checks['listeners']=powershell('Get-NetTCPConnection -State Listen|Select-Object LocalAddress,LocalPort,OwningProcess|ConvertTo-Json -Compress')
        checks['firewall']=powershell('Get-NetFirewallProfile|Select-Object Name,Enabled,DefaultInboundAction|ConvertTo-Json -Compress')
    elif system=='Linux':
        cmds={'os_patch':'uname -a; cat /etc/os-release 2>/dev/null | head -12',
          'antivirus':'systemctl is-active clamav-daemon 2>/dev/null; systemctl is-active falcon-sensor 2>/dev/null; systemctl is-active wazuh-agent 2>/dev/null',
          'encryption':'lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINTS',
          'admins':'getent group sudo; getent group wheel',
          'processes':'ps -eo pid,user,comm --sort=-%cpu | head -80',
          'listeners':'ss -lntup',
          'firewall':'ufw status verbose 2>/dev/null; nft list ruleset 2>/dev/null | head -100; iptables -S 2>/dev/null | head -100'}
        for name,cmd in cmds.items():checks[name]=command(['sh','-c',cmd])
    else:checks['os']={'status':'unknown','evidence':'Unsupported OS'}
    for item in checks.values():
        if item['status']=='needs_review' and any(x in item.get('evidence','').lower() for x in ('access is denied','permission denied','not recognized','not found','requires elevation')):
            item['status']='unknown'
    return {'schema':'1.0','device_id':identity(),'hostname':socket.gethostname(),
      'os':{'name':system,'release':platform.release(),'version':platform.version()},
      'collected_at':datetime.now(timezone.utc).isoformat(),'checks':checks,
      'assessment':'EVIDENCE_ONLY','score':None,
      'note':'No automatic PASS: command success is not evidence of a healthy device. UNKNOWN is never treated as PASS.'}
def identity():
    return hashlib.sha256((socket.gethostname()+'|'+platform.system()).encode()).hexdigest()[:32]
# DPAPI via native Windows API; no plaintext fallback.
class BLOB(ctypes.Structure):
    _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_char))]
def dpapi(data,decrypt=False):
    source=ctypes.create_string_buffer(data)
    inp=BLOB(len(data),ctypes.cast(source,ctypes.POINTER(ctypes.c_char))); out=BLOB()
    lib=ctypes.windll.crypt32
    if decrypt:
        ok=lib.CryptUnprotectData(ctypes.byref(inp),None,None,None,None,0,ctypes.byref(out))
    else:ok=lib.CryptProtectData(ctypes.byref(inp),'ZTNSS device credential',None,None,None,0,ctypes.byref(out))
    if not ok:raise OSError('DPAPI operation failed')
    result=ctypes.string_at(out.pbData,out.cbData)
    ctypes.windll.kernel32.LocalFree(out.pbData)
    return result
def save_token(token):
    HOME.mkdir(mode=0o700,parents=True,exist_ok=True)
    if platform.system()=='Windows':
        CONFIG.write_text(json.dumps({'backend':'dpapi','encrypted':base64.b64encode(dpapi(token.encode())).decode()}))
    else:
        import keyring
        keyring.set_password('ZTNSS-Agent',identity(),token)
        CONFIG.write_text(json.dumps({'backend':'keyring'}))
        CONFIG.chmod(0o600)
def token():
    c=json.loads(CONFIG.read_text())
    if c['backend']=='dpapi':return dpapi(base64.b64decode(c['encrypted']),True).decode()
    import keyring
    value=keyring.get_password('ZTNSS-Agent',identity())
    if not value:raise RuntimeError('Token not found in OS keyring')
    return value
def request(url,body,headers):
    if not url.startswith('https://'):raise RuntimeError('HTTPS is mandatory')
    req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json',**headers},method='POST')
    with urllib.request.urlopen(req,timeout=30) as r:return json.loads(r.read())
def main():
    p=argparse.ArgumentParser();p.add_argument('--controller',required=True)
    group=p.add_mutually_exclusive_group(required=True);group.add_argument('--enroll',action='store_true');group.add_argument('--report',action='store_true');group.add_argument('--uninstall',action='store_true')
    a=p.parse_args()
    if a.uninstall:
        if CONFIG.exists():
            if platform.system()!='Windows':
                import keyring
                try:keyring.delete_password('ZTNSS-Agent',identity())
                except Exception:pass
            CONFIG.unlink()
        print('Local enrollment credentials removed. Ask controller administrator to revoke device enrollment.');return
    if a.enroll:
        secret=os.environ.get('ZTNSS_ENROLLMENT_SECRET','')
        if not secret:raise RuntimeError('Set ZTNSS_ENROLLMENT_SECRET before enrollment')
        body=json.dumps({'device_id':identity(),'hostname':socket.gethostname()}).encode()
        result=request(a.controller.rstrip('/')+'/api/enroll',body,{'X-Enrollment-Secret':secret})
        save_token(result['token']);print('Enrolled device:',result['device_id']);return
    body=json.dumps(collect(),separators=(',',':')).encode();key=token()
    ts=str(int(time.time()));nonce=secrets.token_urlsafe(24)
    sig=hmac.new(key.encode(),ts.encode()+b'\n'+nonce.encode()+b'\n'+body,hashlib.sha256).hexdigest()
    result=request(a.controller.rstrip('/')+'/api/report',body,{'Authorization':'Bearer '+key,'X-ZTNSS-Time':ts,'X-ZTNSS-Nonce':nonce,'X-ZTNSS-Signature':sig})
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
