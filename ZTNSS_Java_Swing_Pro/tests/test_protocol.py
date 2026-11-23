import unittest,hashlib,hmac,time,secrets
class ProtocolTests(unittest.TestCase):
 def test_signature(self):
  key='test';ts=str(int(time.time()));nonce=secrets.token_urlsafe(20);body=b'{"device_id":"abc"}'
  sig=hmac.new(key.encode(),ts.encode()+b"\n"+nonce.encode()+b"\n"+body,hashlib.sha256).hexdigest()
  self.assertEqual(sig,hmac.new(key.encode(),ts.encode()+b"\n"+nonce.encode()+b"\n"+body,hashlib.sha256).hexdigest())
  self.assertNotEqual(sig,hmac.new(key.encode(),ts.encode()+b"\n"+nonce.encode()+b"\n"+b'changed',hashlib.sha256).hexdigest())
 def test_timestamp_window(self):
  self.assertFalse(abs(int(time.time())-(int(time.time())-600))<=300)
if __name__=='__main__':unittest.main()
