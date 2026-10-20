import requests

BASE = 'http://127.0.0.1:5000'
s = requests.Session()

# Login
r = s.post(BASE + '/demo/stage1-login', json={'username':'alice','password':'Demo@1234'})
d = r.json()
fp = d['session_fingerprint']
print('fp:', fp)

# Replay
r2 = s.post(BASE + '/demo/stage2-replay', json={'session_fingerprint': fp})
d2 = r2.json()
print('stage2 full response:')
import json
print(json.dumps(d2, indent=2))
