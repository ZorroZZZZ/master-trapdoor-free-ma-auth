import csv, pathlib, statistics, math, sys
R=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else 'results')
def read(p):
    with open(p,newline='',encoding='utf-8-sig') as f:return list(csv.DictReader(f))
def med(vals):return statistics.median(vals) if vals else float('nan')
lat=[]
for fn in ['stage13c_h32_lattice_raw_latest.csv','stage13c_h64_lattice_raw_latest.csv']:
    p=R/fn
    if p.exists():lat+=read(p)
base=read(R/'stage13c_mldsa_online_raw_latest.csv') if (R/'stage13c_mldsa_online_raw_latest.csv').exists() else []
out=[];ok=True
for prof,H,e in [('H32-NUMERIC-PASS',32,76032),('H64-NUMERIC-PASS-CANDIDATE',64,78336)]:
    ks=sorted({int(r['k']) for r in lat if r['profile']==prof and r['group']=='scale_cross_domain'})
    for k in ks:
        lr=[r for r in lat if r['profile']==prof and int(r['k'])==k and r['group']=='scale_cross_domain']
        br=[r for r in base if r['baseline']=='per_attribute_mldsa' and int(r['k'])==k]
        meas=int(statistics.median([int(r['thin_token_bytes']) for r in lr])) if lr else -1
        pred=8+32+32+e
        bp=8+32+2420*k
        bm=int(statistics.median([int(r['thin_token_bytes']) for r in br])) if br else -1
        byteok=(meas==pred and (not br or bm==bp));ok=ok and byteok
        out.append({'profile':prof,'k':k,'lattice_predicted_thin':pred,'lattice_measured_thin':meas,'perattr_predicted_thin':bp,'perattr_measured_thin':bm,'byte_formula_match':byteok,'lattice_online_sign_ms':med([float(r['online_sign_ms']) for r in lr]),'lattice_online_verify_ms':med([float(r['online_verify_ms']) for r in lr]),'perattr_online_sign_ms':med([float(r['online_sign_ms']) for r in br]),'perattr_online_verify_ms':med([float(r['online_verify_total_ms']) for r in br])})
with open(R/'stage13c_theory_vs_measurement.csv','w',newline='',encoding='utf-8') as f:
    w=csv.DictWriter(f,fieldnames=list(out[0]) if out else ['profile']);w.writeheader();w.writerows(out)
lines=['# Stage 13C break-even report','']
for prof,H,e in [('H32-NUMERIC-PASS',32,76032),('H64-NUMERIC-PASS-CANDIDATE',64,78336)]:
    core=e+32;k=math.ceil(core/2420);adv=(2420*H-core)/(2420*H)*100
    lines += [f'## {prof}',f'- fresh lattice possession core: {core:,} B',f'- theoretical per-attribute ML-DSA crossover: k = {k}',f'- at k={H}: per-attribute ML-DSA = {2420*H:,} B; lattice = {core:,} B; lattice reduction = {adv:.2f}%', '']
(R/'BREAK_EVEN_REPORT.md').write_text('\n'.join(lines),encoding='utf-8')
(R/'STAGE13C_ANALYSIS_VALIDATION.txt').write_text('theory_vs_serialized_bytes='+('PASS' if ok else 'FAIL')+'\nclaim_scope=fresh_online_possession_and_thin_token_only\n',encoding='utf-8')
print('ANALYSIS='+('PASS' if ok else 'FAIL'))
