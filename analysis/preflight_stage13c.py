from pathlib import Path
import csv,hashlib,json,re,sys
R=Path(__file__).resolve().parent
errors=[]
# pinned third-party
p=R/'third_party/mldsa-native-v2.0.0.zip'; exp='c201a7a8467afa5b072ca3007cf91ebb55dd027a8f1dc876adcae3a6ccc8b158'
if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=exp:errors.append('mldsa archive hash')
# Stage13B numeric results
j=json.loads((R/'inputs/stage13b_security/stage13b_candidate_estimator_summary.json').read_text(encoding='utf-8'))
prof={x['H_MAX']:x for x in j['profiles']}
for H in (32,64):
    if H not in prof or prof[H]['numeric_gate']!='PASS_NUMERIC':errors.append(f'H{H} numeric gate')
if prof[64]['nfMLWE_quantum_effective_bits']<128 or prof[64]['homSIS_quantum_effective_bits']<128:errors.append('H64 <128 estimated')
# H128 must not be formal matrix
for fn,H in [('stage13c_h32_matrix.csv',32),('stage13c_h64_matrix.csv',64)]:
    rows=list(csv.DictReader(open(R/'config'/fn,newline='',encoding='utf-8-sig')))
    if not rows:errors.append(fn+' empty')
    if max(int(x['witness_size']) for x in rows)>H:errors.append(fn+' witness cap')
    if min(int(x['trials']) for x in rows)<500:errors.append(fn+' formal trials <500')
# source anchors
s=(R/'src/stage13c_lattice_onlineoffline.cpp').read_text(encoding='utf-8')
for a in ['wid','H32-NUMERIC-PASS','29936088.078136202','4064258089.3915906','H64-NUMERIC-PASS-CANDIDATE','43346104.49987477','5884862290.537376','serialize_token','negative_tests']:
    if a not in s:errors.append('source anchor '+a)
print('PREFLIGHT='+('PASS' if not errors else 'FAIL'))
for e in errors:print('ERROR',e)
sys.exit(0 if not errors else 20)
