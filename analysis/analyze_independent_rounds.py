from pathlib import Path
import argparse, csv, math, random, statistics, hashlib, sys

ap=argparse.ArgumentParser()
ap.add_argument("--root",required=True)
ap.add_argument("--bootstrap-reps",type=int,default=50000)
args=ap.parse_args()
R=Path(args.root)
RES=R/"stats_results"
RAW=RES/"raw"
PROC=RES/"processed"
PROC.mkdir(parents=True,exist_ok=True)

catalog=list(csv.DictReader((R/"config/case_catalog.csv").open(newline="",encoding="utf-8-sig")))
catalog_by={r["case_id"]:r for r in catalog}

def fnum(x):
    try:
        v=float(x)
        return v if math.isfinite(v) else None
    except Exception:
        return None

def pct(xs,p):
    ys=sorted(xs)
    if not ys: return float("nan")
    if len(ys)==1: return ys[0]
    pos=(len(ys)-1)*p
    lo=int(math.floor(pos)); hi=int(math.ceil(pos))
    if lo==hi: return ys[lo]
    z=pos-lo
    return ys[lo]*(1-z)+ys[hi]*z

def boot_ci_median(xs,reps,seed):
    xs=list(xs)
    if not xs: return (float("nan"),float("nan"))
    rng=random.Random(seed)
    n=len(xs)
    boots=[]
    for _ in range(reps):
        boots.append(statistics.median(xs[rng.randrange(n)] for _ in range(n)))
    return pct(boots,.025),pct(boots,.975)

def basic(xs):
    xs=list(xs)
    med=statistics.median(xs)
    q1=pct(xs,.25); q3=pct(xs,.75)
    return med,q1,q3,q3-q1

round_rows=[]
errors=[]
raw_hashes=[]

for rnd in range(1,11):
    rd=RAW/f"round_{rnd:02d}"
    if not rd.exists():
        errors.append(f"missing round {rnd}")
        continue
    for c in catalog:
        cid=c["case_id"]; fam=c["family"]
        od=rd/cid
        val=od/"CASE_VALIDATION.txt"
        if not val.exists() or "overall=PASS" not in val.read_text(encoding="utf-8-sig",errors="replace"):
            errors.append(f"round {rnd} case {cid} validation missing/not PASS")
            continue
        if fam=="lattice":
            p=od/"stage13c_lattice_online_raw.csv"
            rows=list(csv.DictReader(p.open(newline="",encoding="utf-8-sig")))
            metric_cols=["online_sign_ms","samplepre_ms","online_verify_ms","lattice_ms",
                         "hmsg_ms","serialize_ms","norm_over_beta","peak_rss_bytes"]
        else:
            p=od/"stage13c_mldsa_online_raw.csv"
            rows=list(csv.DictReader(p.open(newline="",encoding="utf-8-sig")))
            metric_cols=["online_sign_ms","online_verify_total_ms","online_verify_sig_ms",
                         "current_ms","peak_rss"]
        raw_hashes.append((str(p.relative_to(RES)).replace("\\","/"),hashlib.sha256(p.read_bytes()).hexdigest()))
        if len(rows)!=100:
            errors.append(f"round {rnd} case {cid} rowcount {len(rows)}")
        for m in metric_cols:
            vals=[fnum(x.get(m)) for x in rows]
            vals=[x for x in vals if x is not None]
            if not vals:
                continue
            med,q1,q3,iqr=basic(vals)
            round_rows.append({
                "round":rnd,"case_id":cid,"family":fam,"group":c["group"],
                "k":int(c["k"]),"p":int(c["p"]),"metric":m,"n":len(vals),
                "median":med,"q1":q1,"q3":q3,"iqr":iqr
            })

# Write per-round case stats
fields=["round","case_id","family","group","k","p","metric","n","median","q1","q3","iqr"]
with (PROC/"round_case_statistics.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(round_rows)

# Summary across independent round medians
groups={}
for r in round_rows:
    key=(r["case_id"],r["family"],r["group"],r["k"],r["p"],r["metric"])
    groups.setdefault(key,[]).append(float(r["median"]))

summary=[]
for idx,(key,xs) in enumerate(sorted(groups.items())):
    cid,fam,grp,k,p,m=key
    med,q1,q3,iqr=basic(xs)
    lo,hi=boot_ci_median(xs,args.bootstrap_reps,2026081700+idx)
    mean=statistics.mean(xs)
    sd=statistics.stdev(xs) if len(xs)>1 else 0.0
    cv=(sd/mean) if mean else float("nan")
    summary.append({
        "case_id":cid,"family":fam,"group":grp,"k":k,"p":p,"metric":m,
        "independent_rounds":len(xs),"median_of_round_medians":med,
        "q1_round_medians":q1,"q3_round_medians":q3,"iqr_round_medians":iqr,
        "bootstrap95_low":lo,"bootstrap95_high":hi,
        "min_round_median":min(xs),"max_round_median":max(xs),
        "cv_round_medians":cv
    })

sfields=["case_id","family","group","k","p","metric","independent_rounds",
         "median_of_round_medians","q1_round_medians","q3_round_medians","iqr_round_medians",
         "bootstrap95_low","bootstrap95_high","min_round_median","max_round_median","cv_round_medians"]
with (PROC/"independent_round_summary.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=sfields); w.writeheader(); w.writerows(summary)

# Figure 1 round-level normalization
lookup={(r["round"],r["case_id"],r["metric"]):float(r["median"]) for r in round_rows}
fig_round=[]
for rnd in range(1,11):
    lat_base=lookup.get((rnd,"H64_XD_K01","online_sign_ms"))
    pa_base=lookup.get((rnd,"PA_K01","online_sign_ms"))
    for k in [1,8,16,32,33,48,64]:
        cid=f"H64_XD_K{k:02d}"
        v=lookup.get((rnd,cid,"online_sign_ms"))
        if lat_base and v is not None:
            fig_round.append({"architecture":"Proposed scheme","round":rnd,"k":k,"normalized_signing":v/lat_base})
        cid=f"PA_K{k:02d}"
        v=lookup.get((rnd,cid,"online_sign_ms"))
        if pa_base and v is not None:
            fig_round.append({"architecture":"Per-attribute ML-DSA","round":rnd,"k":k,"normalized_signing":v/pa_base})

with (PROC/"figure1_normalized_signing_rounds.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=["architecture","round","k","normalized_signing"]);w.writeheader();w.writerows(fig_round)

fg={}
for r in fig_round:
    fg.setdefault((r["architecture"],r["k"]),[]).append(float(r["normalized_signing"]))
fig_sum=[]
for idx,((arch,k),xs) in enumerate(sorted(fg.items())):
    med,q1,q3,iqr=basic(xs);lo,hi=boot_ci_median(xs,args.bootstrap_reps,2026082700+idx)
    fig_sum.append({"architecture":arch,"k":k,"rounds":len(xs),"median_ratio":med,
                    "q1":q1,"q3":q3,"iqr":iqr,"bootstrap95_low":lo,"bootstrap95_high":hi})
with (PROC/"figure1_normalized_signing_summary.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=["architecture","k","rounds","median_ratio","q1","q3","iqr","bootstrap95_low","bootstrap95_high"]);w.writeheader();w.writerows(fig_sum)

# Authority-partition summary: publication subset
auth=[r for r in summary if r["family"]=="lattice" and r["group"]=="fixed_witness_partition" and r["metric"] in {"online_sign_ms","samplepre_ms","online_verify_ms"}]
with (PROC/"authority_partition_summary.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=sfields);w.writeheader();w.writerows(auth)

# Paired J64 vs J1 changes within each round
ep=[]
for rnd in range(1,11):
    for metric in ["online_sign_ms","samplepre_ms","online_verify_ms"]:
        a=lookup.get((rnd,"H64_FW64_J01",metric))
        b=lookup.get((rnd,"H64_FW64_J64",metric))
        if a and b is not None:
            ep.append({"round":rnd,"metric":metric,"j1_median":a,"j64_median":b,
                       "ratio_j64_over_j1":b/a,"percent_change":100.0*(b/a-1.0)})
with (PROC/"authority_partition_endpoint_changes.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=["round","metric","j1_median","j64_median","ratio_j64_over_j1","percent_change"]);w.writeheader();w.writerows(ep)

eps=[]
for idx,metric in enumerate(["online_sign_ms","samplepre_ms","online_verify_ms"]):
    xs=[float(r["percent_change"]) for r in ep if r["metric"]==metric]
    if xs:
        med,q1,q3,iqr=basic(xs);lo,hi=boot_ci_median(xs,args.bootstrap_reps,2026083700+idx)
        eps.append({"metric":metric,"rounds":len(xs),"median_percent_change":med,
                    "q1":q1,"q3":q3,"iqr":iqr,"bootstrap95_low":lo,"bootstrap95_high":hi,
                    "min":min(xs),"max":max(xs)})
with (PROC/"authority_partition_endpoint_change_summary.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=["metric","rounds","median_percent_change","q1","q3","iqr","bootstrap95_low","bootstrap95_high","min","max"]);w.writeheader();w.writerows(eps)

# Communication model
comm=[]
for k in range(1,65):
    proposed=78408
    pa=40+2420*k
    periodic=2460
    comm.append({"k":k,"proposed_bytes":proposed,"per_attribute_mldsa_bytes":pa,
                 "periodic_mldsa_bytes":periodic,"proposed_minus_pa":proposed-pa,
                 "proposed_smaller_than_pa":int(proposed<pa)})
with (PROC/"communication_break_even.csv").open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=list(comm[0].keys()));w.writeheader();w.writerows(comm)

# Raw hashes
with (RES/"RAW_ARTIFACT_SHA256.txt").open("w",encoding="utf-8") as f:
    for rel,h in sorted(raw_hashes):
        f.write(f"{h}  {rel}\n")

# Environment consistency: active power-plan GUID should remain unchanged across round snapshots.
import re
power_guids=set()
for snap in sorted((RES/"environment").glob("round_*_snapshot.txt")):
    txt=snap.read_text(encoding="utf-8-sig",errors="replace")
    m=re.search(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",txt)
    if m:
        power_guids.add(m.group(0).lower())
if len(power_guids)>1:
    errors.append("active power plan changed across rounds: "+",".join(sorted(power_guids)))

# Final validation
required_case_count=len(catalog)
expected_round_metric_cases=10*required_case_count
round_case_present={(r["round"],r["case_id"]) for r in round_rows}
if len(round_case_present)!=expected_round_metric_cases:
    errors.append(f"round/case coverage={len(round_case_present)} expected={expected_round_metric_cases}")
for r in summary:
    if int(r["independent_rounds"])!=10:
        errors.append(f"{r['case_id']} {r['metric']} rounds={r['independent_rounds']}")

vlines=[
    "Stage 13E Independent-Round Statistics Validation",
    "rounds_required=10",
    "trials_per_case_per_round=100",
    f"formal_case_count={required_case_count}",
    f"targeted_online_measurements={required_case_count*10*100}",
    f"bootstrap_reps={args.bootstrap_reps}",
    "ci_resampling_unit=independent_round_medians",
    "outlier_policy=retain_all_raw_observations",
    "figure1_normalization=within_round_to_own_k1",
    "power_plan_policy=recorded_not_modified",
    "affinity_policy=recorded_not_modified",
]
if errors:
    vlines += ["overall=FAIL"] + ["error="+e for e in errors]
else:
    vlines += ["overall=PASS"]
(PROC/"STAGE13E_STATS_VALIDATION.txt").write_text("\n".join(vlines)+"\n",encoding="utf-8")

(PROC/"PUBLICATION_STATS_README.txt").write_text(
"""Publication-facing statistics

1. Do not pool 1000 trials and call them 1000 independent machine replicates.
2. Each case has ten independently restarted process medians.
3. Main CI: bootstrap 95% CI over those ten round medians.
4. Figure 1: normalize each round to the same architecture's k=1 median, then summarize the ten ratios.
5. Authority partition: use J={1,4,16,64}; paired J64/J1 percent changes are computed within each round.
6. If small endpoint effects are comparable with round-level variability, use:
   "No distinguishable growth was observed within the measured round-to-round variability."
7. Communication bytes are analytical/serializer-deterministic, not statistical measurements.
""",encoding="utf-8")

print("STAGE13E_ANALYSIS="+("PASS" if not errors else "FAIL"))
print("processed="+str(PROC))
for e in errors: print("ERROR:",e)
sys.exit(0 if not errors else 20)
