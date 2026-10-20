import requests, json

BASE = 'http://127.0.0.1:5000'
s = requests.Session()

print('=== Stage 1: Login ===')
r = s.post(BASE + '/demo/stage1-login', json={'username':'alice','password':'Demo@1234'})
d = r.json()
print('Status:', r.status_code, 'success:', d['success'], 'fp:', d.get('session_fingerprint'))
fp = d['session_fingerprint']

print()
print('=== Stage 2: Replay Attack ===')
r2 = s.post(BASE + '/demo/stage2-replay', json={'session_fingerprint': fp})
d2 = r2.json()
print('Status:', r2.status_code, 'detected:', d2.get('detected'), 'server_code:', d2.get('server_response_code'))

print()
print('=== Stage 3: Detection ===')
r3 = s.post(BASE + '/demo/stage3-detection', json={'session_fingerprint': fp})
d3 = r3.json()
print('Status:', r3.status_code, 'revoked:', d3.get('session_revoked'))

print()
print('=== Stage 4: Verify ===')
r4 = s.post(BASE + '/demo/stage4-verify', json={'session_fingerprint': fp})
d4 = r4.json()
summary = d4.get('demo_summary', {})
print('Overall result:', summary.get('overall_result'))
for k, v in summary.items():
    print(' ', k, ':', v)

print()
print('=== Security Events ===')
evts = s.get(BASE + '/api/security-events').json()['events']
for e in evts[:8]:
    print(' ', e['event_type'], '|', e.get('reason','')[:60], '| outcome:', e.get('outcome'))
