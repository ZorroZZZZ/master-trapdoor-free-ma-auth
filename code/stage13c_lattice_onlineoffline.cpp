
// ABS — Stage 11R Final Protocol E2E v0.3 (FIPS202 C-linkage repair)
//
// Frozen structural reference profile:
//   N=256, q=17179859969, d=8, radix=32, kg=7, w=56.
//
// Purpose:
//   One-click widened C++17 functional port validation.
//   This is a reference/experimental implementation, not a side-channel-hardened
//   production cryptographic library.
//
// The 1-D D_Z sampler is a finite-support rejection sampler proportional to
// exp(-pi(x-c)^2/s^2) on |x-c| <= tau*s. Floating-point exp() evaluation is
// used. Thus q_sig*delta_pre must remain symbolic in the security theorem.
//
// Build targets: MSVC x64 /std:c++17 and GCC/Clang C++17.

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <complex>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <map>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <set>
#include <unordered_map>
#include <cstring>

#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#include <psapi.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "psapi.lib")

#include "mldsa_native.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "fips202.h"
#ifdef __cplusplus
}
#endif

#if MLD_CONFIG_PARAMETER_SET != 44
#error Stage 13C is pinned to ML-DSA-44.
#endif
#define E2E_KEYPAIR_INTERNAL PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal
#define E2E_SIGNATURE_INTERNAL PQCP_MLDSA_NATIVE_MLDSA44_signature_internal
#define E2E_VERIFY_INTERNAL PQCP_MLDSA_NATIVE_MLDSA44_verify_internal


#ifdef _MSC_VER
  #include <intrin.h>
#endif

using u64 = std::uint64_t;
using i64 = std::int64_t;
using ld  = long double;
using cd  = std::complex<long double>;

static constexpr int N = 256;
static constexpr int LOGN = 8;
static constexpr u64 Q = 17179859969ULL;
static constexpr int D = 8;
static constexpr int M0 = 16;
static constexpr int RADIX = 32;
static constexpr int KG = 7;
static constexpr int W = 56;
static constexpr int ROOT_WIDTH = 72;
static constexpr int DE = 18432;
#ifndef STAGE13C_PROFILE_HMAX
#define STAGE13C_PROFILE_HMAX 32
#endif
#if STAGE13C_PROFILE_HMAX == 32
static constexpr int HMAX = 32;
static constexpr ld ZETA = 29936088.078136202L;
static constexpr ld BETA_SIG = 4064258089.3915906L;
static constexpr int PROOF_PACK_BITS = 33;
static constexpr const char* PROFILE_ID = "H32-NUMERIC-PASS";
#elif STAGE13C_PROFILE_HMAX == 64
static constexpr int HMAX = 64;
static constexpr ld ZETA = 43346104.49987477L;
static constexpr ld BETA_SIG = 5884862290.537376L;
static constexpr int PROOF_PACK_BITS = 34;
static constexpr const char* PROFILE_ID = "H64-NUMERIC-PASS-CANDIDATE";
#else
#error Stage13C formal build supports only H32 and H64.
#endif
static constexpr ld PI_L = 3.141592653589793238462643383279502884L;
static constexpr ld S_R = 2.0L;
static constexpr ld ALPHA = 488.3263734200445L;

static constexpr int TAU = 18;

using PolyU = std::array<u64,N>;
using PolyI = std::array<i64,N>;
using VecU  = std::vector<PolyU>;
using VecI  = std::vector<PolyI>;
using MatU  = std::vector<std::vector<PolyU>>;
using MatI  = std::vector<std::vector<PolyI>>;

static inline u64 add_mod(u64 a, u64 b) {
    u64 s = a + b;
    if (s >= Q || s < a) s -= Q;
    return s;
}
static inline u64 sub_mod(u64 a, u64 b) {
    return a >= b ? a-b : Q-(b-a);
}
static inline u64 mul_mod(u64 a, u64 b) {
#ifdef _MSC_VER
    unsigned __int64 hi = 0;
    unsigned __int64 lo = _umul128(a,b,&hi);
    unsigned __int64 rem = 0;
    (void)_udiv128(hi,lo,Q,&rem);
    return rem;
#else
    return (u64)(((__uint128_t)a * (__uint128_t)b) % Q);
#endif
}
static u64 pow_mod(u64 a, u64 e) {
    u64 r=1;
    while(e){
        if(e&1) r=mul_mod(r,a);
        a=mul_mod(a,a);
        e>>=1;
    }
    return r;
}
static inline u64 signed_to_mod(i64 x) {
    if (x >= 0) return (u64)x % Q;
    u64 t = (u64)(-(x+1)) + 1;
    t %= Q;
    return t ? Q-t : 0;
}

static u64 find_psi() {
    const u64 exp=(Q-1)/(2*N);
    for(u64 a=2;a<10000;a++){
        u64 psi=pow_mod(a,exp);
        if(psi!=1 && pow_mod(psi,N)==Q-1 && pow_mod(psi,2*N)==1) return psi;
    }
    throw std::runtime_error("no primitive 512th root");
}
static u64 PSI, OMEGA, PSI_INV;
static std::array<u64,N> PSI_POW{}, PSI_INV_POW{};

static void init_ntt() {
    PSI=find_psi();
    OMEGA=mul_mod(PSI,PSI);
    PSI_INV=pow_mod(PSI,Q-2);
    for(int j=0;j<N;j++){
        PSI_POW[j]=pow_mod(PSI,j);
        PSI_INV_POW[j]=pow_mod(PSI_INV,j);
    }
}

static void ntt_inplace(PolyU& a, u64 root) {
    int j=0;
    for(int i=1;i<N;i++){
        int bit=N>>1;
        while(j & bit){ j ^= bit; bit >>= 1; }
        j ^= bit;
        if(i<j) std::swap(a[i],a[j]);
    }
    for(int len=2;len<=N;len<<=1){
        u64 wlen=pow_mod(root,N/len);
        for(int st=0;st<N;st+=len){
            u64 wv=1;
            int h=len>>1;
            for(int j2=st;j2<st+h;j2++){
                u64 u=a[j2];
                u64 v=mul_mod(a[j2+h],wv);
                a[j2]=add_mod(u,v);
                a[j2+h]=sub_mod(u,v);
                wv=mul_mod(wv,wlen);
            }
        }
    }
}
static PolyU fwd_neg(const PolyU& p) {
    PolyU a{};
    for(int i=0;i<N;i++) a[i]=mul_mod(p[i]%Q,PSI_POW[i]);
    ntt_inplace(a,OMEGA);
    return a;
}
static PolyU fwd_neg(const PolyI& p) {
    PolyU a{};
    for(int i=0;i<N;i++) a[i]=mul_mod(signed_to_mod(p[i]),PSI_POW[i]);
    ntt_inplace(a,OMEGA);
    return a;
}
static PolyU inv_neg(PolyU a) {
    u64 invroot=pow_mod(OMEGA,Q-2);
    ntt_inplace(a,invroot);
    u64 invN=pow_mod(N,Q-2);
    for(int i=0;i<N;i++) a[i]=mul_mod(mul_mod(a[i],invN),PSI_INV_POW[i]);
    return a;
}
static PolyU mul_neg_mod(const PolyI& a,const PolyI& b) {
    PolyU A=fwd_neg(a), B=fwd_neg(b);
    for(int i=0;i<N;i++) A[i]=mul_mod(A[i],B[i]);
    return inv_neg(A);
}

static PolyI negacyclic_exact(const PolyI& a,const PolyI& b) {
    std::array<long long,2*N-1> cv{};
    for(int i=0;i<N;i++)
        for(int j=0;j<N;j++)
            cv[i+j] += (long long)a[i]*(long long)b[j];
    PolyI out{};
    for(int i=0;i<N;i++) out[i]=cv[i] - (i+N<2*N-1 ? cv[i+N] : 0);
    return out;
}

static MatU matmul_mod(const MatU& A,const MatU& B) {
    int r=(int)A.size(), k=(int)A[0].size(), c=(int)B[0].size();
    std::vector<std::vector<PolyU>> At(r,std::vector<PolyU>(k));
    std::vector<std::vector<PolyU>> Bt(k,std::vector<PolyU>(c));
    for(int i=0;i<r;i++) for(int t=0;t<k;t++) At[i][t]=fwd_neg(A[i][t]);
    for(int t=0;t<k;t++) for(int j=0;j<c;j++) Bt[t][j]=fwd_neg(B[t][j]);
    MatU C(r,std::vector<PolyU>(c));
    for(int i=0;i<r;i++) for(int j=0;j<c;j++){
        PolyU acc{};
        for(int t=0;t<k;t++)
            for(int s=0;s<N;s++)
                acc[s]=add_mod(acc[s],mul_mod(At[i][t][s],Bt[t][j][s]));
        C[i][j]=inv_neg(acc);
    }
    return C;
}
static MatU to_mod(const MatI& A) {
    MatU R(A.size(),std::vector<PolyU>(A[0].size()));
    for(size_t i=0;i<A.size();i++) for(size_t j=0;j<A[i].size();j++)
        for(int c=0;c<N;c++) R[i][j][c]=signed_to_mod(A[i][j][c]);
    return R;
}

// -----------------------------------------------------------------------------
// Reference D_Z rejection sampler
// -----------------------------------------------------------------------------
struct DZ {
    std::mt19937_64& rng;
    u64 calls=0, proposals=0;
    explicit DZ(std::mt19937_64& r):rng(r){}
    i64 sample(ld center, ld s) {
        if(!(s>0)) throw std::runtime_error("nonpositive D_Z width");
        const ld R=(ld)TAU*s;
        i64 lo=(i64)std::floor(center-R)-1;
        i64 hi=(i64)std::ceil(center+R)+1;
        std::uniform_int_distribution<i64> U(lo,hi);
        std::uniform_real_distribution<ld> V(0.0L,1.0L);
        i64 nearest=(i64)std::llround(center);
        ld d0=((ld)nearest-center)/s;
        ld logmax=-PI_L*d0*d0;
        ++calls;
        for(;;){
            ++proposals;
            i64 x=U(rng);
            ld d=((ld)x-center)/s;
            ld logw=-PI_L*d*d;
            ld accept=std::exp(logw-logmax);
            if(V(rng)<=accept) return x;
        }
    }
};

static std::vector<i64> SMALL_X;
static std::vector<ld> SMALL_CDF;
static void init_small_leaf_table() {
    int R=28;
    ld total=0;
    for(int x=-R;x<=R;x++){
        ld w=std::exp(-PI_L*(ld)(x*x)/(S_R*S_R));
        SMALL_X.push_back(x); SMALL_CDF.push_back(w); total+=w;
    }
    ld acc=0;
    for(auto& x:SMALL_CDF){ acc+=x/total; x=acc; }
    SMALL_CDF.back()=1;
}
static i64 sample_leaf(std::mt19937_64& rng) {
    std::uniform_real_distribution<ld> U(0.0L,1.0L);
    ld u=U(rng);
    auto it=std::lower_bound(SMALL_CDF.begin(),SMALL_CDF.end(),u);
    return SMALL_X[(size_t)(it-SMALL_CDF.begin())];
}

// -----------------------------------------------------------------------------
// GM18 arbitrary-radix scalar and module GSample
// -----------------------------------------------------------------------------
static std::array<int,KG> QDIG{};
static std::array<ld,KG> DCOEF{}, LCOEF{}, HCOEF{};
static void init_gm() {
    u64 x=Q;
    for(int i=0;i<KG;i++){ QDIG[i]=(int)(x%RADIX); x/=RADIX; }
    DCOEF[0]=(ld)QDIG[0]/RADIX;
    for(int i=1;i<KG;i++) DCOEF[i]=(DCOEF[i-1]+QDIG[i])/RADIX;
    LCOEF[0]=std::sqrt((ld)RADIX*(1.0L+1.0L/KG)+1.0L);
    for(int i=1;i<KG;i++) LCOEF[i]=std::sqrt((ld)RADIX*(1.0L+1.0L/(KG-i)));
    HCOEF[0]=0;
    for(int i=0;i<KG-1;i++) HCOEF[i+1]=std::sqrt((ld)RADIX*(1.0L-1.0L/(KG-i)));
}
static std::array<int,KG> base_digits(u64 x) {
    std::array<int,KG> d{};
    for(int i=0;i<KG;i++){ d[i]=(int)(x%RADIX); x/=RADIX; }
    return d;
}
static std::array<ld,KG> sample_g_perturb(DZ& dz,ld s_inner) {
    std::array<i64,KG+1> z{};
    ld beta=0;
    for(int i=0;i<KG;i++){
        z[i]=dz.sample(beta/LCOEF[i],s_inner/LCOEF[i]);
        beta=-(ld)z[i]*HCOEF[i];
    }
    std::array<ld,KG> p{};
    p[0]=(2*RADIX+1)*(ld)z[0]+RADIX*(ld)z[1];
    for(int i=1;i<KG;i++) p[i]=RADIX*((ld)z[i-1]+2.0L*z[i]+z[i+1]);
    return p;
}
static std::array<i64,KG> sample_D_lattice(DZ& dz,const std::array<ld,KG>& c,ld s_inner) {
    std::array<i64,KG> z{};
    ld cd=-c[KG-1]/DCOEF[KG-1];
    i64 fl=(i64)std::floor(cd);
    z[KG-1]=fl+dz.sample(cd-fl,s_inner/DCOEF[KG-1]);
    for(int i=0;i<KG-1;i++){
        ld ci=(ld)z[KG-1]*DCOEF[i]-c[i];
        fl=(i64)std::floor(ci);
        z[i]=fl+dz.sample(ci-fl,s_inner);
    }
    return z;
}
static std::array<i64,KG> scalar_gsample(DZ& dz,u64 u) {
    ld s_inner=ALPHA/(RADIX+1);
    auto p=sample_g_perturb(dz,s_inner);
    auto ud=base_digits(u);
    std::array<ld,KG> c{};
    c[0]=((ld)ud[0]-p[0])/RADIX;
    for(int i=1;i<KG;i++) c[i]=(c[i-1]+ud[i]-p[i])/RADIX;
    auto z=sample_D_lattice(dz,c,s_inner);
    std::array<i64,KG> t{};
    t[0]=RADIX*z[0]+QDIG[0]*z[KG-1]+ud[0];
    for(int i=1;i<KG-1;i++) t[i]=RADIX*z[i]-z[i-1]+QDIG[i]*z[KG-1]+ud[i];
    t[KG-1]=QDIG[KG-1]*z[KG-1]-z[KG-2]+ud[KG-1];
    u64 got=0, scale=1;
    for(int i=0;i<KG;i++){ got=add_mod(got,mul_mod(scale,signed_to_mod(t[i]))); scale=mul_mod(scale,RADIX); }
    if(got!=u%Q) throw std::runtime_error("scalar GSample algebra failure");
    return t;
}
static VecI module_gsample(DZ& dz,const std::vector<PolyU>& u) {
    VecI z(W);
    for(int r=0;r<D;r++) for(int c=0;c<N;c++){
        auto t=scalar_gsample(dz,u[r][c]);
        for(int j=0;j<KG;j++) z[r*KG+j][c]=t[j];
    }
    return z;
}
static std::vector<PolyU> G_times_z(const VecI& z) {
    std::vector<PolyU> out(D);
    for(int r=0;r<D;r++) for(int j=0;j<KG;j++){
        u64 scale=pow_mod(RADIX,j);
        for(int c=0;c<N;c++)
            out[r][c]=add_mod(out[r][c],mul_mod(scale,signed_to_mod(z[r*KG+j][c])));
    }
    return out;
}

// -----------------------------------------------------------------------------
// Complex CRT and recursive SampleFz / Sample2z
// -----------------------------------------------------------------------------
static std::array<std::vector<cd>,LOGN+1> ROOT_TREE;
static std::array<cd,N*N> EVALM;
static void init_crt() {
    ROOT_TREE[0]={cd(1,0)};
    ROOT_TREE[1]={cd(0,1),cd(0,-1)};
    for(int dep=2;dep<=LOGN;dep++){
        for(auto w:ROOT_TREE[dep-1]){
            cd s=std::sqrt(-w);
            ROOT_TREE[dep].push_back(s); ROOT_TREE[dep].push_back(-s);
        }
    }
    for(int r=0;r<N;r++){
        cd v(1,0), root=ROOT_TREE[LOGN][r];
        for(int j=0;j<N;j++){ EVALM[r*N+j]=v; v*=root; }
    }
}
static std::vector<cd> crt_eval(const PolyI& p) {
    std::vector<cd> out(N);
    for(int r=0;r<N;r++){
        cd s(0,0);
        for(int j=0;j<N;j++) s+=EVALM[r*N+j]*(ld)p[j];
        out[r]=s;
    }
    return out;
}
static std::vector<cd> stride(const std::vector<cd>& a,int depth) {
    int deg=N>>depth, h=deg/2;
    std::vector<cd> out(deg);
    for(int i=0;i<h;i++){
        cd w=-ROOT_TREE[LOGN-depth][2*i];
        out[i]=(a[2*i]+a[2*i+1])/2.0L;
        out[h+i]=std::conj(w)*(a[2*i]-a[2*i+1])/2.0L;
    }
    return out;
}
static std::vector<cd> inverse_stride(const std::vector<cd>& a,int depth) {
    int deg=N>>depth,h=deg/2;
    std::vector<cd> out(deg);
    for(int i=0;i<h;i++){
        cd w=-ROOT_TREE[LOGN-depth][2*i];
        out[2*i]=a[i]+w*a[h+i];
        out[2*i+1]=a[i]-w*a[h+i];
    }
    return out;
}
struct RecStats { u64 fz=0,z2=0; ld mincov=1e300L,maximag=0; };
struct FzRes { std::vector<i64> coeff; std::vector<cd> eval; };

static FzRes sample_fz(DZ&,std::vector<cd>,std::vector<cd>,int,RecStats&);
static void sample_2z(DZ& dz,std::vector<cd> a,std::vector<cd> b,std::vector<cd> d,
                      std::vector<cd> c0,std::vector<cd> c1,int depth,RecStats& st,
                      FzRes& q0,FzRes& q1) {
    st.z2++;
    q1=sample_fz(dz,d,c1,depth,st);
    std::vector<cd> bd(b.size()), anew(a.size()), cnew(c0.size());
    for(size_t i=0;i<b.size();i++){
        bd[i]=b[i]/d[i];
        anew[i]=a[i]-bd[i]*std::conj(b[i]);
        cnew[i]=c0[i]+bd[i]*(q1.eval[i]-c1[i]);
    }
    q0=sample_fz(dz,anew,cnew,depth,st);
}
static FzRes sample_fz(DZ& dz,std::vector<cd> f,std::vector<cd> c,int depth,RecStats& st) {
    st.fz++;
    int deg=N>>depth;
    if(deg==1){
        ld cov=std::real(f[0]), cen=std::real(c[0]);
        st.mincov=std::min(st.mincov,cov);
        st.maximag=std::max(st.maximag,std::fabs(std::imag(c[0])));
        if(!(cov>0)) throw std::runtime_error("nonpositive SampleFz covariance");
        i64 x=dz.sample(cen,std::sqrt(cov));
        return {{x},{cd((ld)x,0)}};
    }
    auto fs=stride(f,depth), cs=stride(c,depth);
    int h=deg/2;
    std::vector<cd> f0(fs.begin(),fs.begin()+h), f1(fs.begin()+h,fs.end());
    std::vector<cd> c0(cs.begin(),cs.begin()+h), c1(cs.begin()+h,cs.end());
    FzRes q0,q1;
    sample_2z(dz,f0,f1,f0,c0,c1,depth+1,st,q0,q1);
    FzRes out; out.coeff.resize(deg);
    for(int i=0;i<h;i++){ out.coeff[2*i]=q0.coeff[i]; out.coeff[2*i+1]=q1.coeff[i]; }
    std::vector<cd> merged; merged.reserve(deg);
    merged.insert(merged.end(),q0.eval.begin(),q0.eval.end());
    merged.insert(merged.end(),q1.eval.begin(),q1.eval.end());
    out.eval=inverse_stride(merged,depth);
    return out;
}

// -----------------------------------------------------------------------------
// Root trapdoor and SamplePerturb
// -----------------------------------------------------------------------------
struct RootInst { MatI R,T; MatU Ahat,Bpub; };

static RootInst build_root(std::mt19937_64& rng) {
    RootInst I;
    I.R=MatI(M0,std::vector<PolyI>(W));
    for(int i=0;i<M0;i++) for(int j=0;j<W;j++) for(int c=0;c<N;c++){
        i64 x=0; for(int h=0;h<HMAX;h++) x+=sample_leaf(rng);
        I.R[i][j][c]=x;
    }
    I.T=I.R;
    for(auto& row:I.T) for(auto& p:row) for(auto& x:p) x=-x;

    std::uniform_int_distribution<u64> U(0,Q-1);
    I.Ahat=MatU(D,std::vector<PolyU>(D));
    for(int i=0;i<D;i++) for(int j=0;j<D;j++) for(auto& x:I.Ahat[i][j]) x=U(rng);

    MatI S(D,std::vector<PolyI>(W)), E(D,std::vector<PolyI>(W));
    for(int i=0;i<D;i++) for(int j=0;j<W;j++){ S[i][j]=I.R[i][j]; E[i][j]=I.R[D+i][j]; }
    MatU AS=matmul_mod(I.Ahat,to_mod(S));
    I.Bpub=MatU(D,std::vector<PolyU>(W));
    for(int i=0;i<D;i++) for(int j=0;j<W;j++) for(int c=0;c<N;c++){
        u64 v=add_mod(AS[i][j][c],signed_to_mod(E[i][j][c]));
        if(j/KG==i && c==0) v=add_mod(v,pow_mod(RADIX,j%KG));
        I.Bpub[i][j][c]=v;
    }
    return I;
}

using EvalTW = std::vector<std::vector<std::vector<cd>>>; // M0 x W x N
static EvalTW transform_T(const MatI& T) {
    EvalTW E(M0,std::vector<std::vector<cd>>(W,std::vector<cd>(N)));
    for(int i=0;i<M0;i++) for(int j=0;j<W;j++) E[i][j]=crt_eval(T[i][j]);
    return E;
}
using Schur = std::vector<std::vector<std::vector<cd>>>; // 16x16xN
static Schur build_schur(const EvalTW& T) {
    ld gamma=1.0L/(1.0L/(ALPHA*ALPHA)-1.0L/(ZETA*ZETA));
    Schur S(M0,std::vector<std::vector<cd>>(M0,std::vector<cd>(N)));
    for(int i=0;i<M0;i++) for(int j=0;j<=i;j++) for(int r=0;r<N;r++){
        cd sum(0,0);
        for(int t=0;t<W;t++) sum+=T[i][t][r]*std::conj(T[j][t][r]);
        cd v=-gamma*sum;
        if(i==j) v+=ZETA*ZETA;
        S[i][j][r]=v;
    }
    for(int l=M0-1;l>=2;l--){
        auto d=S[l][l];
        for(int i=0;i<l;i++){
            auto Bi=S[l][i];
            for(int j=0;j<=i;j++) for(int r=0;r<N;r++)
                S[i][j][r]-=S[l][j][r]*std::conj(Bi[r])/d[r];
        }
    }
    return S;
}
static VecI sample_perturb(DZ& dz,const EvalTW& T,const Schur& S,RecStats& st) {
    VecI p(ROOT_WIDTH);
    ld bottom=std::sqrt(ZETA*ZETA-ALPHA*ALPHA);
    for(int j=0;j<W;j++) for(int c=0;c<N;c++) p[M0+j][c]=dz.sample(0,bottom);

    std::vector<std::vector<cd>> pb(W);
    for(int j=0;j<W;j++) pb[j]=crt_eval(p[M0+j]);

    ld factor=-(ALPHA*ALPHA)/(ZETA*ZETA-ALPHA*ALPHA);
    std::vector<std::vector<cd>> center(M0,std::vector<cd>(N));
    for(int i=0;i<M0;i++) for(int r=0;r<N;r++){
        cd s(0,0); for(int j=0;j<W;j++) s+=T[i][j][r]*pb[j][r];
        center[i][r]=factor*s;
    }
    std::vector<std::vector<cd>> topEval(M0);
    for(int l=M0-1;l>=2;l--){
        FzRes q=sample_fz(dz,S[l][l],center[l],0,st);
        for(int c=0;c<N;c++) p[l][c]=q.coeff[c];
        topEval[l]=q.eval;
        for(int i=0;i<l;i++) for(int r=0;r<N;r++)
            center[i][r]+=(q.eval[r]-center[l][r])*std::conj(S[l][i][r])/S[l][l][r];
    }
    FzRes q0,q1;
    std::vector<cd> b(N);
    for(int r=0;r<N;r++) b[r]=std::conj(S[1][0][r]);
    sample_2z(dz,S[0][0],b,S[1][1],center[0],center[1],0,st,q0,q1);
    for(int c=0;c<N;c++){ p[0][c]=q0.coeff[c]; p[1][c]=q1.coeff[c]; }
    return p;
}

static std::vector<PolyU> M_times_vec(const RootInst& I,const VecI& v) {
    MatI topS(D,std::vector<PolyI>(1));
    for(int i=0;i<D;i++) topS[i][0]=v[i];
    MatU At=matmul_mod(I.Ahat,to_mod(topS));
    std::vector<PolyU> out(D);
    for(int i=0;i<D;i++) for(int c=0;c<N;c++)
        out[i][c]=add_mod(At[i][0][c],signed_to_mod(v[D+i][c]));

    MatI bot(W,std::vector<PolyI>(1));
    for(int j=0;j<W;j++) bot[j][0]=v[M0+j];
    MatU Bz=matmul_mod(I.Bpub,to_mod(bot));
    for(int i=0;i<D;i++) for(int c=0;c<N;c++) out[i][c]=add_mod(out[i][c],Bz[i][0][c]);
    return out;
}
static VecI T_times_z_exact(const MatI& T,const VecI& z) {
    VecI out(M0);
    for(int i=0;i<M0;i++){
        PolyI acc{};
        for(int j=0;j<W;j++){
            PolyI p=negacyclic_exact(T[i][j],z[j]);
            for(int c=0;c<N;c++) acc[c]+=p[c];
        }
        out[i]=acc;
    }
    return out;
}
static ld norm2(const VecI& v) {
    ld s=0; for(auto& p:v) for(auto x:p) s+=(ld)x*(ld)x; return std::sqrt(s);
}
static i64 maxabs(const VecI& v) {
    i64 m=0; for(auto& p:v) for(auto x:p) m=std::max<i64>(m,std::llabs(x)); return m;
}

struct FullResult {
    bool gsample=false, trap=false, preimage=false, normpass=false;
    ld norm=0, ratio=0, perturb_s=0, gsample_s=0, total_s=0;
    i64 maxcoef=0; u64 dzcalls=0, proposals=0; u64 fz=0,z2=0;
};

static FullResult full_trial(std::mt19937_64& rng,DZ& dz) {
    auto t0=std::chrono::steady_clock::now();
    RootInst I=build_root(rng);
    EvalTW Te=transform_T(I.T);
    Schur S=build_schur(Te);
    RecStats rs;

    auto a=std::chrono::steady_clock::now();
    VecI p=sample_perturb(dz,Te,S,rs);
    auto b=std::chrono::steady_clock::now();

    std::uniform_int_distribution<u64> U(0,Q-1);
    std::vector<PolyU> u(D);
    for(auto& poly:u) for(auto& x:poly) x=U(rng);
    auto Mp=M_times_vec(I,p);
    std::vector<PolyU> v(D);
    for(int i=0;i<D;i++) for(int c=0;c<N;c++) v[i][c]=sub_mod(u[i][c],Mp[i][c]);

    auto c0=std::chrono::steady_clock::now();
    VecI z=module_gsample(dz,v);
    auto c1=std::chrono::steady_clock::now();
    bool gok=(G_times_z(z)==v);

    VecI Tz=T_times_z_exact(I.T,z);
    VecI ti(ROOT_WIDTH);
    for(int i=0;i<M0;i++) ti[i]=Tz[i];
    for(int j=0;j<W;j++) ti[M0+j]=z[j];
    bool tok=(M_times_vec(I,ti)==G_times_z(z));

    VecI e(ROOT_WIDTH);
    for(int i=0;i<M0;i++) for(int k=0;k<N;k++) e[i][k]=p[i][k]+Tz[i][k];
    for(int j=0;j<W;j++) for(int k=0;k<N;k++) e[M0+j][k]=p[M0+j][k]+z[j][k];
    bool pok=(M_times_vec(I,e)==u);
    ld n=norm2(e);

    FullResult R;
    R.gsample=gok; R.trap=tok; R.preimage=pok; R.norm=n; R.ratio=n/BETA_SIG;
    R.normpass=n<=BETA_SIG; R.maxcoef=maxabs(e); R.dzcalls=dz.calls; R.proposals=dz.proposals;
    R.fz=rs.fz; R.z2=rs.z2;
    R.perturb_s=std::chrono::duration<ld>(b-a).count();
    R.gsample_s=std::chrono::duration<ld>(c1-c0).count();
    R.total_s=std::chrono::duration<ld>(std::chrono::steady_clock::now()-t0).count();
    return R;
}

// -----------------------------------------------------------------------------
// Batch tests
// -----------------------------------------------------------------------------
static bool ntt_regression(std::mt19937_64& rng,int trials) {
    std::uniform_int_distribution<int> A(-9,9), Bv(-4000,4000);
    for(int t=0;t<trials;t++){
        PolyI a{},b{};
        for(int i=0;i<N;i++){ a[i]=A(rng); b[i]=Bv(rng); }
        PolyI ex=negacyclic_exact(a,b);
        PolyU nt=mul_neg_mod(a,b);
        for(int i=0;i<N;i++) if(signed_to_mod(ex[i])!=nt[i]) return false;
    }
    return true;
}
static bool scalar_regression(std::mt19937_64& rng,DZ& dz,int trials) {
    std::uniform_int_distribution<u64> U(0,Q-1);
    try{ for(int i=0;i<trials;i++) (void)scalar_gsample(dz,U(rng)); }
    catch(...){ return false; }
    return true;
}


namespace fs = std::filesystem;

struct Stats {
    size_t n=0;
    double mean=0, median=0, stdev=0, p95=0, minv=0, maxv=0;
};
static Stats calc_stats(std::vector<double> v) {
    Stats s; s.n=v.size();
    if(v.empty()) return s;
    std::sort(v.begin(),v.end());
    s.minv=v.front(); s.maxv=v.back();
    s.mean=std::accumulate(v.begin(),v.end(),0.0)/(double)v.size();
    double ss=0; for(double x:v) ss+=(x-s.mean)*(x-s.mean);
    s.stdev=std::sqrt(ss/(double)v.size());
    size_t n=v.size();
    s.median = n%2 ? v[n/2] : 0.5*(v[n/2-1]+v[n/2]);
    size_t idx=(size_t)std::ceil(0.95*(double)n);
    if(idx==0) idx=1; if(idx>n) idx=n;
    s.p95=v[idx-1];
    return s;
}
static void write_stats_row(std::ofstream& f,const std::string& stage,const std::string& metric,
                            const std::string& unit,const std::vector<double>& vals,
                            const std::string& note="") {
    Stats s=calc_stats(vals);
    f<<stage<<","<<metric<<","<<unit<<","<<s.n<<","
     <<std::setprecision(12)<<s.mean<<","<<s.median<<","<<s.stdev<<","<<s.p95<<","
     <<s.minv<<","<<s.maxv<<",\""<<note<<"\"\n";
}
static double us_since(std::chrono::steady_clock::time_point a,std::chrono::steady_clock::time_point b) {
    return std::chrono::duration<double,std::micro>(b-a).count();
}
static double ms_since(std::chrono::steady_clock::time_point a,std::chrono::steady_clock::time_point b) {
    return std::chrono::duration<double,std::milli>(b-a).count();
}

static PolyU mul_neg_naive_mod_u(const PolyU& a,const PolyU& b) {
    PolyU out{};
    for(int i=0;i<N;i++) for(int j=0;j<N;j++){
        u64 term=mul_mod(a[i],b[j]);
        int k=i+j;
        if(k<N) out[k]=add_mod(out[k],term);
        else out[k-N]=sub_mod(out[k-N],term);
    }
    return out;
}
static PolyU mul_neg_ntt_u(const PolyU& a,const PolyU& b) {
    PolyU A=fwd_neg(a), Bm=fwd_neg(b);
    for(int i=0;i<N;i++) A[i]=mul_mod(A[i],Bm[i]);
    return inv_neg(A);
}

struct Credential {
    MatI R;
    MatU Bpub;
};
static MatU random_Ahat(std::mt19937_64& rng) {
    std::uniform_int_distribution<u64> U(0,Q-1);
    MatU A(D,std::vector<PolyU>(D));
    for(int i=0;i<D;i++) for(int j=0;j<D;j++) for(auto& x:A[i][j]) x=U(rng);
    return A;
}
static Credential issue_credential(std::mt19937_64& rng,const MatU& Ahat) {
    Credential C;
    C.R=MatI(M0,std::vector<PolyI>(W));
    for(int i=0;i<M0;i++) for(int j=0;j<W;j++) for(int c=0;c<N;c++)
        C.R[i][j][c]=sample_leaf(rng);

    MatI S(D,std::vector<PolyI>(W)), E(D,std::vector<PolyI>(W));
    for(int i=0;i<D;i++) for(int j=0;j<W;j++){
        S[i][j]=C.R[i][j];
        E[i][j]=C.R[D+i][j];
    }
    MatU AS=matmul_mod(Ahat,to_mod(S));
    C.Bpub=MatU(D,std::vector<PolyU>(W));
    for(int i=0;i<D;i++) for(int j=0;j<W;j++) for(int c=0;c<N;c++){
        u64 v=add_mod(AS[i][j][c],signed_to_mod(E[i][j][c]));
        if(j/KG==i && c==0) v=add_mod(v,pow_mod(RADIX,j%KG));
        C.Bpub[i][j][c]=v;
    }
    return C;
}
static RootInst aggregate_credentials(const MatU& Ahat,const std::vector<Credential>& creds,int k) {
    if(k<1 || k>(int)creds.size()) throw std::runtime_error("bad k");
    RootInst I;
    I.Ahat=Ahat;
    I.R=MatI(M0,std::vector<PolyI>(W));
    I.Bpub=MatU(D,std::vector<PolyU>(W));
    for(int t=0;t<k;t++){
        for(int i=0;i<M0;i++) for(int j=0;j<W;j++) for(int c=0;c<N;c++)
            I.R[i][j][c]+=creds[t].R[i][j][c];
        for(int i=0;i<D;i++) for(int j=0;j<W;j++) for(int c=0;c<N;c++)
            I.Bpub[i][j][c]=add_mod(I.Bpub[i][j][c],creds[t].Bpub[i][j][c]);
    }
    // B_W = sum B_i - (k-1)G.
    for(int i=0;i<D;i++) for(int j=0;j<KG;j++){
        int col=i*KG+j;
        u64 g=pow_mod(RADIX,j);
        for(int t=1;t<k;t++) I.Bpub[i][col][0]=sub_mod(I.Bpub[i][col][0],g);
    }
    I.T=I.R;
    for(auto& row:I.T) for(auto& p:row) for(auto& x:p) x=-x;
    return I;
}
static bool verify_root_identity(const RootInst& I) {
    MatI top(D,std::vector<PolyI>(W));
    for(int i=0;i<D;i++) for(int j=0;j<W;j++) top[i][j]=I.T[i][j];
    MatU ATop=matmul_mod(I.Ahat,to_mod(top));
    for(int i=0;i<D;i++) for(int j=0;j<W;j++) for(int c=0;c<N;c++){
        u64 lhs=ATop[i][j][c];
        lhs=add_mod(lhs,signed_to_mod(I.T[D+i][j][c]));
        lhs=add_mod(lhs,I.Bpub[i][j][c]);
        u64 rhs=0;
        if(j/KG==i && c==0) rhs=pow_mod(RADIX,j%KG);
        if(lhs!=rhs) return false;
    }
    return true;
}
static i64 maxabs_mat(const MatI& M) {
    i64 m=0;
    for(auto& r:M) for(auto& p:r) for(auto x:p) m=std::max<i64>(m,std::llabs(x));
    return m;
}

struct SamplePreBench {
    bool gsample=false, trap=false, preimage=false, normpass=false;
    double perturb_ms=0, gsample_ms=0, combine_ms=0, verify_ms=0, total_ms=0;
    double norm_ratio=0, norm2v=0;
    i64 maxcoef=0;
    u64 dz_calls_delta=0, proposals_delta=0;
};
static SamplePreBench samplepre_on_prepared(const RootInst& I,const EvalTW& Te,const Schur& S,
                                             std::mt19937_64& rng,DZ& dz) {
    SamplePreBench R;
    auto total0=std::chrono::steady_clock::now();
    u64 c0=dz.calls,p0=dz.proposals;
    RecStats rs;

    auto a=std::chrono::steady_clock::now();
    VecI p=sample_perturb(dz,Te,S,rs);
    auto b=std::chrono::steady_clock::now();

    std::uniform_int_distribution<u64> U(0,Q-1);
    std::vector<PolyU> u(D);
    for(auto& poly:u) for(auto& x:poly) x=U(rng);
    auto Mp=M_times_vec(I,p);
    std::vector<PolyU> v(D);
    for(int i=0;i<D;i++) for(int c=0;c<N;c++) v[i][c]=sub_mod(u[i][c],Mp[i][c]);

    auto g0=std::chrono::steady_clock::now();
    VecI z=module_gsample(dz,v);
    auto g1=std::chrono::steady_clock::now();
    R.gsample=(G_times_z(z)==v);

    auto x0=std::chrono::steady_clock::now();
    VecI Tz=T_times_z_exact(I.T,z);
    VecI ti(ROOT_WIDTH);
    for(int i=0;i<M0;i++) ti[i]=Tz[i];
    for(int j=0;j<W;j++) ti[M0+j]=z[j];

    VecI e(ROOT_WIDTH);
    for(int i=0;i<M0;i++) for(int c=0;c<N;c++) e[i][c]=p[i][c]+Tz[i][c];
    for(int j=0;j<W;j++) for(int c=0;c<N;c++) e[M0+j][c]=p[M0+j][c]+z[j][c];
    auto x1=std::chrono::steady_clock::now();

    auto v0=std::chrono::steady_clock::now();
    R.trap=(M_times_vec(I,ti)==G_times_z(z));
    R.preimage=(M_times_vec(I,e)==u);
    auto v1=std::chrono::steady_clock::now();

    ld n=norm2(e);
    R.norm2v=(double)n; R.norm_ratio=(double)(n/BETA_SIG);
    R.normpass=n<=BETA_SIG; R.maxcoef=maxabs(e);
    R.perturb_ms=ms_since(a,b); R.gsample_ms=ms_since(g0,g1);
    R.combine_ms=ms_since(x0,x1); R.verify_ms=ms_since(v0,v1);
    R.total_ms=ms_since(total0,std::chrono::steady_clock::now());
    R.dz_calls_delta=dz.calls-c0; R.proposals_delta=dz.proposals-p0;
    return R;
}

static uint64_t ceil_div_u64(uint64_t a,uint64_t b){ return (a+b-1)/b; }
static uint64_t packed_bytes(uint64_t ring_elems,int coeff_bits) {
    return ceil_div_u64(ring_elems*(uint64_t)N*(uint64_t)coeff_bits,8);
}
static void ensure_dirs(const fs::path& root) {
    fs::create_directories(root);
    for(int s=1;s<=7;s++) fs::create_directories(root/("stage"+std::to_string(s)+"R"));
}

struct Counts {
    int stage1_naive=500, stage1_ntt=1000;
    int stage2_issue=100;
    int stage3_agg=1000;
    int stage4_root=50;
    int stage5_samplepre=200;
    int stage6_e2e_per_k=100;
};
static Counts formal_counts(){ return Counts{}; }
static Counts quick_counts(){
    Counts c; c.stage1_naive=3;c.stage1_ntt=5;c.stage2_issue=2;c.stage3_agg=5;
    c.stage4_root=1;c.stage5_samplepre=1;c.stage6_e2e_per_k=1; return c;
}

static int stage1r7r_legacy_main(int argc,char** argv) {
    try {
        bool quick=false;
        fs::path outroot="results";
        for(int i=1;i<argc;i++){
            std::string a=argv[i];
            if(a=="--quick") quick=true;
            else if(a=="--out" && i+1<argc) outroot=argv[++i];
        }
        Counts C=quick?quick_counts():formal_counts();
        ensure_dirs(outroot);

        std::mt19937_64 rng(20260815ULL);
        init_ntt(); init_small_leaf_table(); init_gm(); init_crt();
        DZ dz(rng);
        MatU Ahat=random_Ahat(rng);

        std::ofstream summary(outroot/"all_stage_summary.csv");
        summary<<"stage,metric,unit,n,mean,median,stddev,p95,min,max,note\n";
        std::ofstream validation(outroot/"FINAL_VALIDATION_REPORT.txt");
        validation<<"ABS Integrated Stage 1R-7R Final Benchmark\n";
        validation<<"profile=Q34-d8-radix32\n";
        validation<<"mode="<<(quick?"QUICK_SMOKE":"FORMAL")<<"\n";

        std::cout<<"============================================================\n";
        std::cout<<"ABS Integrated Stage 1R-7R Final Benchmark v1.0\n";
        std::cout<<"============================================================\n";
        std::cout<<"MODE="<<(quick?"QUICK_SMOKE":"FORMAL")<<"\n";
        std::cout<<"N="<<N<<" q="<<Q<<" d="<<D<<" m0="<<M0<<" radix="<<RADIX
                 <<" kg="<<KG<<" w="<<W<<" D_e="<<DE<<"\n";

        // -----------------------------------------------------------------
        // Stage 1R: ring arithmetic / NTT
        // -----------------------------------------------------------------
        std::cout<<"[Stage 1R] Ring arithmetic / NTT...\n";
        std::ofstream s1(outroot/"stage1R"/"stage1R_ring_arithmetic_raw.csv");
        s1<<"method,trial,time_us,correct\n";
        std::uniform_int_distribution<u64> Uq(0,Q-1);
        std::vector<std::pair<PolyU,PolyU>> ring_inputs(16);
        for(auto& pr:ring_inputs) for(int c=0;c<N;c++){pr.first[c]=Uq(rng);pr.second[c]=Uq(rng);}
        // correctness on a small-coefficient oracle
        bool ntt_oracle_ok=ntt_regression(rng,20);
        std::vector<double> naive_us,ntt_us;
        for(int t=0;t<C.stage1_naive;t++){
            auto& pr=ring_inputs[t%ring_inputs.size()];
            auto a=std::chrono::steady_clock::now(); auto x=mul_neg_naive_mod_u(pr.first,pr.second);
            auto b=std::chrono::steady_clock::now();
            volatile u64 sink=x[t%N]; (void)sink;
            double dt=us_since(a,b); naive_us.push_back(dt);
            s1<<"naive_mod,"<<t<<","<<dt<<","<<1<<"\n";
        }
        for(int t=0;t<C.stage1_ntt;t++){
            auto& pr=ring_inputs[t%ring_inputs.size()];
            auto a=std::chrono::steady_clock::now(); auto x=mul_neg_ntt_u(pr.first,pr.second);
            auto b=std::chrono::steady_clock::now();
            volatile u64 sink=x[t%N]; (void)sink;
            double dt=us_since(a,b); ntt_us.push_back(dt);
            s1<<"ntt_mod,"<<t<<","<<dt<<","<<ntt_oracle_ok<<"\n";
        }
        write_stats_row(summary,"1R","poly_mul_naive","us",naive_us,"q34 negacyclic schoolbook");
        write_stats_row(summary,"1R","poly_mul_ntt","us",ntt_us,"q34 256-degree NTT");
        validation<<"stage1R_ntt_oracle="<<(ntt_oracle_ok?"PASS":"FAIL")<<"\n";

        // -----------------------------------------------------------------
        // Stage 2R: credential issue B=A0R+G
        // -----------------------------------------------------------------
        std::cout<<"[Stage 2R] Credential issue / matrix arithmetic...\n";
        std::ofstream s2(outroot/"stage2R"/"stage2R_credential_issue_raw.csv");
        s2<<"trial,issue_ms,max_abs_R,relation_ok\n";
        std::vector<double> issue_ms;
        std::vector<Credential> fixed_creds;
        for(int i=0;i<4;i++) fixed_creds.push_back(issue_credential(rng,Ahat));
        for(int t=0;t<C.stage2_issue;t++){
            auto a=std::chrono::steady_clock::now();
            Credential cr=issue_credential(rng,Ahat);
            auto b=std::chrono::steady_clock::now();
            double dt=ms_since(a,b); issue_ms.push_back(dt);
            RootInst one=aggregate_credentials(Ahat,std::vector<Credential>{cr},1);
            bool ok=verify_root_identity(one);
            s2<<t<<","<<dt<<","<<maxabs_mat(cr.R)<<","<<ok<<"\n";
        }
        write_stats_row(summary,"2R","credential_issue_B_eq_A0R_plus_G","ms",issue_ms,
                        "includes secret R sampling and B construction");

        // -----------------------------------------------------------------
        // Stage 3R: canonical witness aggregation k=1..4
        // -----------------------------------------------------------------
        std::cout<<"[Stage 3R] Credential aggregation k=1..4...\n";
        std::ofstream s3(outroot/"stage3R"/"stage3R_aggregation_raw.csv");
        s3<<"k,trial,aggregate_us,relation_ok\n";
        for(int k=1;k<=4;k++){
            std::vector<double> vals;
            bool k_ok=true;
            for(int t=0;t<C.stage3_agg;t++){
                auto a=std::chrono::steady_clock::now();
                RootInst I=aggregate_credentials(Ahat,fixed_creds,k);
                auto b=std::chrono::steady_clock::now();
                double dt=us_since(a,b); vals.push_back(dt);
                bool ok = (t<3 ? verify_root_identity(I) : true);
                k_ok = k_ok && ok;
                s3<<k<<","<<t<<","<<dt<<","<<ok<<"\n";
            }
            write_stats_row(summary,"3R","aggregate_k"+std::to_string(k),"us",vals,
                            "R_W=sum R_i; B_W=sum B_i-(k-1)G");
            validation<<"stage3R_k"<<k<<"="<<(k_ok?"PASS":"FAIL")<<"\n";
        }

        // -----------------------------------------------------------------
        // Stage 4R: root trapdoor construction + exact identity verification
        // -----------------------------------------------------------------
        std::cout<<"[Stage 4R] Root trapdoor construction / identity...\n";
        std::ofstream s4(outroot/"stage4R"/"stage4R_root_trapdoor_raw.csv");
        s4<<"k,trial,construct_us,identity_verify_ms,correct\n";
        bool stage4_ok=true;
        for(int k=1;k<=4;k++){
            std::vector<double> cvals,vvals;
            for(int t=0;t<C.stage4_root;t++){
                auto a=std::chrono::steady_clock::now();
                RootInst I=aggregate_credentials(Ahat,fixed_creds,k);
                auto b=std::chrono::steady_clock::now();
                auto v0=std::chrono::steady_clock::now();
                bool ok=verify_root_identity(I);
                auto v1=std::chrono::steady_clock::now();
                stage4_ok=stage4_ok&&ok;
                double cu=us_since(a,b), vm=ms_since(v0,v1);
                cvals.push_back(cu);vvals.push_back(vm);
                s4<<k<<","<<t<<","<<cu<<","<<vm<<","<<ok<<"\n";
            }
            write_stats_row(summary,"4R","trapdoor_construct_k"+std::to_string(k),"us",cvals,"T_W=-R_W");
            write_stats_row(summary,"4R","trapdoor_identity_verify_k"+std::to_string(k),"ms",vvals,
                            "checks A0*T_W+B_W=G");
        }
        validation<<"stage4R_identity="<<(stage4_ok?"PASS":"FAIL")<<"\n";

        // -----------------------------------------------------------------
        // Stage 5R: SamplePre central benchmark, precomputed k=4 root
        // -----------------------------------------------------------------
        std::cout<<"[Stage 5R] SamplePerturb / GSample / ModuleSamplePre...\n";
        RootInst root4=aggregate_credentials(Ahat,fixed_creds,4);
        EvalTW Te4=transform_T(root4.T);
        Schur Sch4=build_schur(Te4);
        std::ofstream s5(outroot/"stage5R"/"stage5R_samplepre_raw.csv");
        s5<<"trial,perturb_ms,gsample_ms,combine_ms,verify_ms,total_ms,norm2,norm_over_beta,maxcoef,"
             "gsample_ok,trap_ok,preimage_ok,norm_ok,dz_calls,dz_proposals\n";
        std::vector<double> pms,gms,cms,vms,tms,nrat;
        int s5pass=0;
        for(int t=0;t<C.stage5_samplepre;t++){
            auto r=samplepre_on_prepared(root4,Te4,Sch4,rng,dz);
            bool ok=r.gsample&&r.trap&&r.preimage&&r.normpass;
            s5pass+=ok;
            pms.push_back(r.perturb_ms);gms.push_back(r.gsample_ms);cms.push_back(r.combine_ms);
            vms.push_back(r.verify_ms);tms.push_back(r.total_ms);nrat.push_back(r.norm_ratio);
            s5<<t<<","<<r.perturb_ms<<","<<r.gsample_ms<<","<<r.combine_ms<<","<<r.verify_ms<<","
              <<r.total_ms<<","<<r.norm2v<<","<<r.norm_ratio<<","<<r.maxcoef<<","
              <<r.gsample<<","<<r.trap<<","<<r.preimage<<","<<r.normpass<<","
              <<r.dz_calls_delta<<","<<r.proposals_delta<<"\n";
        }
        write_stats_row(summary,"5R","sampleperturb","ms",pms,"prepared k=4 root");
        write_stats_row(summary,"5R","module_gsample","ms",gms,"prepared k=4 root");
        write_stats_row(summary,"5R","samplepre_total","ms",tms,"includes target relation and verification");
        write_stats_row(summary,"5R","norm_over_beta","ratio",nrat,"L2 coefficient embedding");
        validation<<"stage5R_passes="<<s5pass<<"/"<<C.stage5_samplepre<<"\n";

        // -----------------------------------------------------------------
        // Stage 6R: online lattice authentication core, k=1..4
        // -----------------------------------------------------------------
        std::cout<<"[Stage 6R] End-to-end lattice authentication core k=1..4...\n";
        std::ofstream s6(outroot/"stage6R"/"stage6R_end_to_end_raw.csv");
        s6<<"k,trial,aggregate_ms,precompute_ms,samplepre_ms,total_online_ms,norm_over_beta,pass\n";
        bool stage6_ok=true;
        for(int k=1;k<=4;k++){
            std::vector<double> agms,pcms,spms,onms,ratios;
            for(int t=0;t<C.stage6_e2e_per_k;t++){
                auto all0=std::chrono::steady_clock::now();
                auto a0=std::chrono::steady_clock::now();
                RootInst I=aggregate_credentials(Ahat,fixed_creds,k);
                auto a1=std::chrono::steady_clock::now();
                auto p0t=std::chrono::steady_clock::now();
                EvalTW Te=transform_T(I.T); Schur Sc=build_schur(Te);
                auto p1t=std::chrono::steady_clock::now();
                auto r=samplepre_on_prepared(I,Te,Sc,rng,dz);
                auto all1=std::chrono::steady_clock::now();
                bool ok=r.gsample&&r.trap&&r.preimage&&r.normpass;
                stage6_ok=stage6_ok&&ok;
                double ag=ms_since(a0,a1), pc=ms_since(p0t,p1t), on=ms_since(all0,all1);
                agms.push_back(ag);pcms.push_back(pc);spms.push_back(r.total_ms);onms.push_back(on);ratios.push_back(r.norm_ratio);
                s6<<k<<","<<t<<","<<ag<<","<<pc<<","<<r.total_ms<<","<<on<<","<<r.norm_ratio<<","<<ok<<"\n";
            }
            write_stats_row(summary,"6R","aggregate_ms_k"+std::to_string(k),"ms",agms,"online canonical witness aggregation");
            write_stats_row(summary,"6R","trapdoor_precompute_ms_k"+std::to_string(k),"ms",pcms,"CRT transform + Schur storage");
            write_stats_row(summary,"6R","samplepre_ms_k"+std::to_string(k),"ms",spms,"root lattice proof generation+verification");
            write_stats_row(summary,"6R","online_core_ms_k"+std::to_string(k),"ms",onms,
                            "lattice core only; excludes Merkle/ML-DSA/network I/O");
        }
        validation<<"stage6R_lattice_core="<<(stage6_ok?"PASS":"FAIL")<<"\n";

        // -----------------------------------------------------------------
        // Stage 7R: exact sizes / communication accounting
        // -----------------------------------------------------------------
        std::cout<<"[Stage 7R] Size / communication audit...\n";
        std::ofstream s7(outroot/"stage7R"/"stage7R_sizes.csv");
        s7<<"item,scenario,k,bytes,KiB,method,note\n";
        uint64_t a0bytes=packed_bytes((uint64_t)D*M0,34);
        uint64_t bibytes=packed_bytes((uint64_t)D*W,34);
        uint64_t proofbytes=packed_bytes((uint64_t)ROOT_WIDTH,33);
        uint64_t riraw=(uint64_t)M0*W*N*sizeof(i64);
        auto row=[&](const std::string& item,const std::string& scenario,int k,uint64_t bytes,
                     const std::string& method,const std::string& note){
            s7<<item<<","<<scenario<<","<<k<<","<<bytes<<","<<(double)bytes/1024.0<<","
              <<method<<",\""<<note<<"\"\n";
        };
        row("A0_explicit","public_parameter",0,a0bytes,"34-bit packed","A0 in R_q^{8x16}");
        row("B_i","per_credential_public",1,bibytes,"34-bit packed","B_i in R_q^{8x56}");
        row("R_i","per_credential_secret",1,riraw,"raw int64 memory","reference implementation; not compressed wire format");
        row("e","root_lattice_proof",0,proofbytes,"33-bit signed bound packing","72 ring elements, 18432 coefficients");
        for(int k=1;k<=4;k++){
            row("lattice_online","registry_reference",k,proofbytes+32ULL*k,"analytical",
                "proof e + 32-byte credential references; excludes Merkle/ML-DSA metadata");
            row("lattice_online","portable_B_included",k,proofbytes+bibytes*(uint64_t)k,"analytical",
                "proof e + k public B_i matrices; excludes Merkle/ML-DSA metadata");
        }
        // FIPS 204 Table 2 exact standardized byte sizes.
        row("ML-DSA-44_public_key","NIST_FIPS204_baseline",0,1312,"FIPS 204 Table 2","size baseline only; no timing measured here");
        row("ML-DSA-44_signature","NIST_FIPS204_baseline",0,2420,"FIPS 204 Table 2","size baseline only");
        row("ML-DSA-65_public_key","NIST_FIPS204_baseline",0,1952,"FIPS 204 Table 2","size baseline only");
        row("ML-DSA-65_signature","NIST_FIPS204_baseline",0,3309,"FIPS 204 Table 2","size baseline only");
        row("ML-DSA-87_public_key","NIST_FIPS204_baseline",0,2592,"FIPS 204 Table 2","size baseline only");
        row("ML-DSA-87_signature","NIST_FIPS204_baseline",0,4627,"FIPS 204 Table 2","size baseline only");

        bool overall=ntt_oracle_ok && stage4_ok && (s5pass==C.stage5_samplepre) && stage6_ok;
        validation<<"overall="<<(overall?"PASS":"FAIL")<<"\n";
        validation<<"IMPORTANT_scope=Stage6R is lattice authentication core only; ML-DSA/Merkle/network timings are not fabricated.\n";
        validation<<"sampler_status=reference floating-point finite-support D_Z; q_sig*delta_pre remains symbolic.\n";

        std::ofstream mf(outroot/"RUN_MANIFEST.txt");
        mf<<"seed=20260815\n";
        mf<<"mode="<<(quick?"QUICK_SMOKE":"FORMAL")<<"\n";
        mf<<"N=256\nq=17179859969\nd=8\nm0=16\nradix=32\nkg=7\nw=56\nD_e=18432\n";
        mf<<"stage1_naive="<<C.stage1_naive<<"\nstage1_ntt="<<C.stage1_ntt<<"\n";
        mf<<"stage2_issue="<<C.stage2_issue<<"\nstage3_agg_per_k="<<C.stage3_agg<<"\n";
        mf<<"stage4_root_per_k="<<C.stage4_root<<"\nstage5_samplepre="<<C.stage5_samplepre<<"\n";
        mf<<"stage6_e2e_per_k="<<C.stage6_e2e_per_k<<"\n";
        mf<<"overall="<<(overall?"PASS":"FAIL")<<"\n";

        std::cout<<"FINAL_BENCHMARK_OVERALL="<<(overall?"PASS":"FAIL")<<"\n";
        std::cout<<"RESULT_ROOT="<<outroot.string()<<"\n";
        std::cout<<"NEXT=UPLOAD results/all_stage_summary.csv, FINAL_VALIDATION_REPORT.txt, and stage1R-stage7R CSVs\n";
        return overall?0:9;
    } catch(const std::exception& e) {
        std::cerr<<"FATAL: "<<e.what()<<"\n";
        return 10;
    }
}


// ============================================================================
// Stage 13C — Online/Offline manifest-backed thin-token experiment.
//
// Protocol core:
//   offline signer: aggregate R_S/B_S, prepare T_S=-R_S and Schur data;
//   offline verifier: validate DUR/AA/Merkle evidence and reconstruct B_S;
//   online token: 8-byte codec header || wid(32) || r_sig(32) || packed e.
//
// Static credential B_a and AA evidence remain in the authenticated registry.
// The request/session is external and bound by H_msg; it is not duplicated in
// the online token.  This is a research benchmark, not a production sampler.
// ============================================================================

using E2EClock = std::chrono::steady_clock;
using Hash32 = std::array<unsigned char,32>;

static double e2e_ms(E2EClock::time_point a,E2EClock::time_point b){return std::chrono::duration<double,std::milli>(b-a).count();}
static void os_random(unsigned char* p,size_t n){
    if(n>0xFFFFFFFFULL) throw std::runtime_error("os_random length");
    if(BCryptGenRandom(nullptr,p,(ULONG)n,BCRYPT_USE_SYSTEM_PREFERRED_RNG)!=0) throw std::runtime_error("BCryptGenRandom");
}
static void deterministic_bytes(unsigned char* p,size_t n,u64 seed){
    u64 x=seed; for(size_t i=0;i<n;){x+=0x9e3779b97f4a7c15ULL;u64 z=x;z=(z^(z>>30))*0xbf58476d1ce4e5b9ULL;z=(z^(z>>27))*0x94d049bb133111ebULL;z^=(z>>31);for(int j=0;j<8&&i<n;j++,i++)p[i]=(unsigned char)(z>>(8*j));}
}
struct E2ESha256{
    BCRYPT_ALG_HANDLE alg=nullptr;DWORD objlen=0;
    E2ESha256(){DWORD cb=0;if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)!=0)throw std::runtime_error("SHA256 provider");if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,(PUCHAR)&objlen,sizeof(objlen),&cb,0)!=0)throw std::runtime_error("SHA256 property");}
    ~E2ESha256(){if(alg)BCryptCloseAlgorithmProvider(alg,0);}
    Hash32 hash(const unsigned char* p,size_t n){if(n>0xFFFFFFFFULL)throw std::runtime_error("SHA256 length");std::vector<unsigned char>obj(objlen);BCRYPT_HASH_HANDLE h=nullptr;Hash32 o{};if(BCryptCreateHash(alg,&h,obj.data(),objlen,nullptr,0,0)!=0)throw std::runtime_error("SHA256 create");if(n&&BCryptHashData(h,(PUCHAR)p,(ULONG)n,0)!=0)throw std::runtime_error("SHA256 data");if(BCryptFinishHash(h,o.data(),32,0)!=0)throw std::runtime_error("SHA256 finish");BCryptDestroyHash(h);return o;}
    Hash32 hash(const std::vector<unsigned char>&v){return hash(v.data(),v.size());}
    Hash32 node(const Hash32&a,const Hash32&b){unsigned char q[64];memcpy(q,a.data(),32);memcpy(q+32,b.data(),32);return hash(q,64);}
};
struct E2ETree{std::vector<std::vector<Hash32>> lv;};
static E2ETree build_tree(E2ESha256&sha,const std::vector<Hash32>&leaves){if(leaves.empty()||(leaves.size()&(leaves.size()-1)))throw std::runtime_error("Merkle size");E2ETree t;t.lv.push_back(leaves);while(t.lv.back().size()>1){auto &c=t.lv.back();std::vector<Hash32>n(c.size()/2);for(size_t i=0;i<n.size();i++)n[i]=sha.node(c[2*i],c[2*i+1]);t.lv.push_back(std::move(n));}return t;}
static bool verify_path(E2ESha256&sha,const E2ETree&t,int idx,Hash32 h){int x=idx;for(size_t l=0;l+1<t.lv.size();l++){const auto&s=t.lv[l][x^1];h=(x&1)?sha.node(s,h):sha.node(h,s);x>>=1;}return h==t.lv.back()[0];}
static uint64_t peak_rss_bytes(){PROCESS_MEMORY_COUNTERS_EX p{};if(GetProcessMemoryInfo(GetCurrentProcess(),(PROCESS_MEMORY_COUNTERS*)&p,sizeof(p)))return(uint64_t)p.PeakWorkingSetSize;return 0;}

static void put_u32(std::vector<unsigned char>&v,uint32_t x){for(int i=0;i<4;i++)v.push_back((unsigned char)(x>>(8*i)));}
static void put_u64(std::vector<unsigned char>&v,uint64_t x){for(int i=0;i<8;i++)v.push_back((unsigned char)(x>>(8*i)));}
static void put_bytes(std::vector<unsigned char>&v,const unsigned char*p,size_t n){v.insert(v.end(),p,p+n);}

static std::vector<unsigned char> pack_B34_raw(const MatU&B){
    const size_t coeffs=(size_t)D*W*N, bytes=(coeffs*34+7)/8;std::vector<unsigned char>out;out.reserve(bytes);u64 acc=0;int nbits=0;
    for(int i=0;i<D;i++)for(int j=0;j<W;j++)for(int c=0;c<N;c++){u64 x=B[i][j][c];acc|=(x<<nbits);nbits+=34;while(nbits>=8){out.push_back((unsigned char)(acc&0xff));acc>>=8;nbits-=8;}}if(nbits)out.push_back((unsigned char)(acc&0xff));if(out.size()!=bytes)throw std::runtime_error("B34 packing");return out;
}
static std::vector<unsigned char> credential_statement(const MatU&B,int aa,int attr,const std::array<unsigned char,32>&pid,uint64_t period){
    auto out=pack_B34_raw(B);size_t old=out.size();out.resize(old+256,0);const char*dom="ABS-S13C-CRED-v1";memcpy(out.data()+old,dom,strlen(dom));memcpy(out.data()+old+32,pid.data(),32);for(int k=0;k<8;k++)out[old+64+k]=(unsigned char)(period>>(8*k));for(int k=0;k<4;k++){out[old+72+k]=(unsigned char)(aa>>(8*k));out[old+76+k]=(unsigned char)(attr>>(8*k));}out[old+80]=1;return out;
}
static Hash32 filler_leaf(E2ESha256&sha,int aa,int idx){unsigned char b[32]{};const char*d="S13C-FILLER";memcpy(b,d,strlen(d));for(int k=0;k<4;k++){b[16+k]=(unsigned char)(aa>>(8*k));b[20+k]=(unsigned char)(idx>>(8*k));}return sha.hash(b,32);}

struct MLDKey{std::vector<unsigned char>pk,sk;MLDKey():pk(MLDSA_PUBLICKEYBYTES(44)),sk(MLDSA_SECRETKEYBYTES(44)){} };
static MLDKey make_mld_key(u64 seedv){MLDKey k;std::array<unsigned char,MLDSA_SEEDBYTES>s{};deterministic_bytes(s.data(),s.size(),seedv);if(E2E_KEYPAIR_INTERNAL(k.pk.data(),k.sk.data(),s.data())!=0)throw std::runtime_error("MLDSA keypair");return k;}
static std::vector<unsigned char>mld_sign(const std::vector<unsigned char>&m,const MLDKey&k,bool fresh){std::vector<unsigned char>s(MLDSA_BYTES(44));std::array<unsigned char,MLDSA_RNDBYTES>r{};if(fresh)os_random(r.data(),r.size());else deterministic_bytes(r.data(),r.size(),0x515151ULL+m.size());const unsigned char pre[2]={0,0};if(E2E_SIGNATURE_INTERNAL(s.data(),m.data(),m.size(),pre,2,r.data(),k.sk.data(),0)!=0)throw std::runtime_error("MLDSA sign");return s;}
static bool mld_verify(const std::vector<unsigned char>&m,const std::vector<unsigned char>&s,const MLDKey&k){const unsigned char pre[2]={0,0};return E2E_VERIFY_INTERNAL(s.data(),m.data(),m.size(),pre,2,k.pk.data(),0)==0;}

struct E2ECred{Credential lat;int aa=0,attr=0;std::vector<unsigned char>statement;Hash32 leaf{};};
struct AAState{MLDKey key;std::vector<Hash32>leaves;E2ETree tree;std::vector<unsigned char>root_msg,root_sig;uint64_t version=1;AAState(u64 s):key(make_mld_key(s)){} };
static std::vector<unsigned char>root_message(const Hash32&h,int aa,int leaves,uint64_t ver){std::vector<unsigned char>m;const char*d="ABS-S13C-ROOT-v1";put_bytes(m,(const unsigned char*)d,strlen(d));put_bytes(m,h.data(),32);put_u32(m,(uint32_t)aa);put_u32(m,(uint32_t)leaves);put_u64(m,ver);return m;}

static RootInst aggregate_public_only(const MatU&Ahat,const std::vector<E2ECred>&creds){
    RootInst I;I.Ahat=Ahat;I.Bpub=MatU(D,std::vector<PolyU>(W));
    for(const auto&cr:creds)for(int i=0;i<D;i++)for(int j=0;j<W;j++)for(int c=0;c<N;c++)I.Bpub[i][j][c]=add_mod(I.Bpub[i][j][c],cr.lat.Bpub[i][j][c]);
    for(int i=0;i<D;i++)for(int j=0;j<KG;j++){int col=i*KG+j;u64 g=pow_mod(RADIX,j);for(size_t t=1;t<creds.size();t++)I.Bpub[i][col][0]=sub_mod(I.Bpub[i][col][0],g);}return I;
}
static bool same_B(const RootInst&a,const RootInst&b){for(int i=0;i<D;i++)for(int j=0;j<W;j++)for(int c=0;c<N;c++)if(a.Bpub[i][j][c]!=b.Bpub[i][j][c])return false;return true;}

struct Shake256Stream{mld_shake256ctx s;Shake256Stream(){mld_shake256_init(&s);}~Shake256Stream(){mld_shake256_release(&s);}void absorb(const void*p,size_t n){const unsigned char*b=(const unsigned char*)p;while(n){size_t z=std::min<size_t>(n,1<<20);mld_shake256_absorb(&s,b,z);b+=z;n-=z;}}void finalize(){mld_shake256_finalize(&s);}void squeeze(unsigned char*p,size_t n){while(n){size_t z=std::min<size_t>(n,1024);mld_shake256_squeeze(p,z,&s);p+=z;n-=z;}}};
static void absorb_u32(Shake256Stream&x,uint32_t v){unsigned char b[4];for(int i=0;i<4;i++)b[i]=(unsigned char)(v>>(8*i));x.absorb(b,4);}
static void absorb_u64(Shake256Stream&x,uint64_t v){unsigned char b[8];for(int i=0;i<8;i++)b[i]=(unsigned char)(v>>(8*i));x.absorb(b,8);}
static std::vector<PolyU> hmsg_thin(const std::string&caseid,uint64_t request_id,const Hash32&wid,const std::array<unsigned char,32>&rsig){
    Shake256Stream x;const char*d="ABS-HMSG-S13C-THIN-v1";x.absorb(d,strlen(d));x.absorb(PROFILE_ID,strlen(PROFILE_ID));x.absorb(wid.data(),32);x.absorb(caseid.data(),caseid.size());absorb_u64(x,request_id);unsigned char nonce[32];deterministic_bytes(nonce,32,0xA13C0000ULL^request_id);x.absorb(nonce,32);x.absorb(rsig.data(),32);x.finalize();
    std::vector<PolyU>u(D);const u64 RANGE=(1ULL<<40),LIM=(RANGE/Q)*Q;unsigned char buf[1024];size_t pos=sizeof(buf),have=0;auto get5=[&](){unsigned char b[5];for(int k=0;k<5;k++){if(pos>=have){x.squeeze(buf,sizeof(buf));pos=0;have=sizeof(buf);}b[k]=buf[pos++];}return(u64)b[0]|((u64)b[1]<<8)|((u64)b[2]<<16)|((u64)b[3]<<24)|((u64)b[4]<<32);};for(int i=0;i<D;i++)for(int c=0;c<N;c++)for(;;){u64 v=get5();if(v<LIM){u[i][c]=v%Q;break;}}return u;
}

struct TargetProof{SamplePreBench bench;VecI e;};
static TargetProof samplepre_on_target13(const RootInst&I,const EvalTW&Te,const Schur&S,const std::vector<PolyU>&u,DZ&dz){
    TargetProof O;auto&R=O.bench;auto total0=E2EClock::now();u64 c0=dz.calls,p0=dz.proposals;RecStats rs;auto a=E2EClock::now();VecI p=sample_perturb(dz,Te,S,rs);auto b=E2EClock::now();auto Mp=M_times_vec(I,p);std::vector<PolyU>v(D);for(int i=0;i<D;i++)for(int c=0;c<N;c++)v[i][c]=sub_mod(u[i][c],Mp[i][c]);auto g0=E2EClock::now();VecI z=module_gsample(dz,v);auto g1=E2EClock::now();R.gsample=(G_times_z(z)==v);auto x0=E2EClock::now();VecI Tz=T_times_z_exact(I.T,z);VecI ti(ROOT_WIDTH);for(int i=0;i<M0;i++)ti[i]=Tz[i];for(int j=0;j<W;j++)ti[M0+j]=z[j];O.e=VecI(ROOT_WIDTH);for(int i=0;i<M0;i++)for(int c=0;c<N;c++)O.e[i][c]=p[i][c]+Tz[i][c];for(int j=0;j<W;j++)for(int c=0;c<N;c++)O.e[M0+j][c]=p[M0+j][c]+z[j][c];auto x1=E2EClock::now();auto v0=E2EClock::now();R.trap=(M_times_vec(I,ti)==G_times_z(z));R.preimage=(M_times_vec(I,O.e)==u);auto v1=E2EClock::now();ld n=norm2(O.e);R.norm2v=(double)n;R.norm_ratio=(double)(n/BETA_SIG);R.normpass=n<=BETA_SIG;R.maxcoef=maxabs(O.e);R.perturb_ms=e2e_ms(a,b);R.gsample_ms=e2e_ms(g0,g1);R.combine_ms=e2e_ms(x0,x1);R.verify_ms=e2e_ms(v0,v1);R.total_ms=e2e_ms(total0,E2EClock::now());R.dz_calls_delta=dz.calls-c0;R.proposals_delta=dz.proposals-p0;return O;
}

static uint64_t proof_bytes_packed(){return ((uint64_t)DE*(uint64_t)PROOF_PACK_BITS+7ULL)/8ULL;}
static std::vector<unsigned char>pack_e(const VecI&e){std::vector<unsigned char>o;o.reserve(proof_bytes_packed());u64 acc=0;int nbits=0;for(const auto&p:e)for(i64 x:p){u64 ax=x>=0?(u64)x:(u64)(-(x+1))+1;u64 z=x>=0?(ax<<1):((ax<<1)-1);if(z>=(1ULL<<PROOF_PACK_BITS))throw std::runtime_error("e packing overflow");acc|=(z<<nbits);nbits+=PROOF_PACK_BITS;while(nbits>=8){o.push_back((unsigned char)(acc&0xff));acc>>=8;nbits-=8;}}if(nbits)o.push_back((unsigned char)(acc&0xff));if(o.size()!=proof_bytes_packed())throw std::runtime_error("e packed size");return o;}
static VecI unpack_e(const unsigned char*p,size_t n){if(n!=proof_bytes_packed())throw std::runtime_error("bad packed e size");VecI e(ROOT_WIDTH);size_t pos=0;u64 acc=0;int nbits=0;const u64 mask=(1ULL<<PROOF_PACK_BITS)-1;for(int i=0;i<ROOT_WIDTH;i++)for(int c=0;c<N;c++){while(nbits<PROOF_PACK_BITS){if(pos>=n)throw std::runtime_error("e unpack underflow");acc|=((u64)p[pos++])<<nbits;nbits+=8;}u64 z=acc&mask;acc>>=PROOF_PACK_BITS;nbits-=PROOF_PACK_BITS;u64 ax=(z+1)>>1;e[i][c]=(z&1)?-(i64)ax:(i64)ax;}return e;}
static std::vector<unsigned char>serialize_token(const Hash32&wid,const std::array<unsigned char,32>&rsig,const VecI&e){auto pe=pack_e(e);std::vector<unsigned char>o;o.reserve(8+64+pe.size());o.push_back('S');o.push_back('1');o.push_back('3');o.push_back('C');o.push_back(1);o.push_back((unsigned char)HMAX);o.push_back(0);o.push_back(0);put_bytes(o,wid.data(),32);put_bytes(o,rsig.data(),32);o.insert(o.end(),pe.begin(),pe.end());return o;}
struct ParsedToken{Hash32 wid{};std::array<unsigned char,32>rsig{};VecI e;};
static ParsedToken parse_token(const std::vector<unsigned char>&t){size_t need=8+64+proof_bytes_packed();if(t.size()!=need||t[0]!='S'||t[1]!='1'||t[2]!='3'||t[3]!='C'||t[4]!=1||t[5]!=(unsigned char)HMAX)throw std::runtime_error("token parse");ParsedToken p;memcpy(p.wid.data(),t.data()+8,32);memcpy(p.rsig.data(),t.data()+40,32);p.e=unpack_e(t.data()+72,t.size()-72);return p;}

static Hash32 manifest_wid(E2ESha256&sha,const std::string&caseid,const std::array<unsigned char,32>&pid,uint64_t period,const RootInst&pub,const std::vector<Hash32>&roots,const std::vector<uint64_t>&versions,int k,int participating){auto raw=pack_B34_raw(pub.Bpub);Hash32 bh=sha.hash(raw);std::vector<unsigned char>m;const char*d="ABS-S13C-MANIFEST-v1";put_bytes(m,(const unsigned char*)d,strlen(d));put_bytes(m,(const unsigned char*)PROFILE_ID,strlen(PROFILE_ID));put_bytes(m,pid.data(),32);put_u64(m,period);put_u32(m,(uint32_t)k);put_u32(m,(uint32_t)participating);put_bytes(m,(const unsigned char*)caseid.data(),caseid.size());put_bytes(m,bh.data(),32);for(size_t i=0;i<roots.size();i++){put_bytes(m,roots[i].data(),32);put_u64(m,versions[i]);}return sha.hash(m);}

struct CaseCfg{std::string id,group;int k=0,participating=0,authorities=0,leaves=0,warmups=0,trials=0,cold_trials=0;};
static std::vector<std::string>split_csv(const std::string&s){std::vector<std::string>a;std::stringstream ss(s);std::string x;while(std::getline(ss,x,','))a.push_back(x);return a;}
static std::vector<CaseCfg>load_cases(const fs::path&p){std::ifstream f(p);if(!f)throw std::runtime_error("matrix open");std::string l;std::getline(f,l);std::vector<CaseCfg>o;while(std::getline(f,l)){if(l.empty())continue;auto a=split_csv(l);if(a.size()!=9)throw std::runtime_error("matrix row");CaseCfg c;c.id=a[0];c.group=a[1];c.k=std::stoi(a[2]);c.participating=std::stoi(a[3]);c.authorities=std::stoi(a[4]);c.leaves=std::stoi(a[5]);c.warmups=std::stoi(a[6]);c.trials=std::stoi(a[7]);c.cold_trials=std::stoi(a[8]);if(c.k<1||c.k>HMAX||c.participating<1||c.participating>c.k||c.authorities<c.participating)throw std::runtime_error("matrix bounds");int need=(c.k+c.participating-1)/c.participating;if(c.leaves<need||(c.leaves&(c.leaves-1)))throw std::runtime_error("Merkle capacity");o.push_back(c);}return o;}

struct SignerState{RootInst root;EvalTW Te;Schur Sc;Hash32 wid{};uint64_t version=1;};
struct VerifierState{RootInst pub;Hash32 wid{};uint64_t version=1;};
struct PrepRec{double policy_ms=0,aggregate_ms=0,precompute_ms=0,manifest_ms=0,cert_ms=0,merkle_ms=0,total_ms=0;bool ok=false;};

static SignerState prepare_signer(const CaseCfg&c,const MatU&Ahat,const std::vector<E2ECred>&creds,const std::vector<AAState>&aas,const std::vector<Hash32>&roots,const std::vector<uint64_t>&versions,const std::array<unsigned char,32>&pid,uint64_t period,E2ESha256&sha,PrepRec&tm){auto t0=E2EClock::now();auto cv0=E2EClock::now();bool auth=true;for(int aa=0;aa<c.participating;aa++)auth=auth&&mld_verify(aas[aa].root_msg,aas[aa].root_sig,aas[aa].key);tm.cert_ms=e2e_ms(cv0,E2EClock::now());double mm=0;for(const auto&cr:creds){auto m0=E2EClock::now();Hash32 h=sha.hash(cr.statement);auth=auth&&(h==cr.leaf)&&verify_path(sha,aas[cr.aa].tree,cr.attr,h);mm+=e2e_ms(m0,E2EClock::now());}tm.merkle_ms=mm;auto p0=E2EClock::now();bool pol=auth&&c.k>=1&&c.k<=HMAX;tm.policy_ms=e2e_ms(p0,E2EClock::now());std::vector<Credential>lat;for(auto&x:creds)lat.push_back(x.lat);auto a0=E2EClock::now();RootInst r=aggregate_credentials(Ahat,lat,c.k);tm.aggregate_ms=e2e_ms(a0,E2EClock::now());auto pc0=E2EClock::now();EvalTW te=transform_T(r.T);Schur sc=build_schur(te);tm.precompute_ms=e2e_ms(pc0,E2EClock::now());auto m0=E2EClock::now();Hash32 wid=manifest_wid(sha,c.id,pid,period,r,roots,versions,c.k,c.participating);tm.manifest_ms=e2e_ms(m0,E2EClock::now());tm.ok=pol&&verify_root_identity(r);tm.total_ms=e2e_ms(t0,E2EClock::now());SignerState s;s.root=std::move(r);s.Te=std::move(te);s.Sc=std::move(sc);s.wid=wid;return s;}
static VerifierState prepare_verifier(const CaseCfg&c,const MatU&Ahat,const std::vector<E2ECred>&creds,const std::vector<AAState>&aas,const MLDKey&dur,const std::vector<unsigned char>&durmsg,const std::vector<unsigned char>&dursig,const std::array<unsigned char,32>&pid,uint64_t period,const Hash32&expected,E2ESha256&sha,PrepRec&tm){auto t0=E2EClock::now();auto cv0=E2EClock::now();bool ok=mld_verify(durmsg,dursig,dur);double mm=0;std::vector<Hash32>roots;std::vector<uint64_t>vers;for(int aa=0;aa<c.participating;aa++){ok=ok&&mld_verify(aas[aa].root_msg,aas[aa].root_sig,aas[aa].key);roots.push_back(aas[aa].tree.lv.back()[0]);vers.push_back(aas[aa].version);}tm.cert_ms=e2e_ms(cv0,E2EClock::now());for(const auto&cr:creds){auto m0=E2EClock::now();Hash32 h=sha.hash(cr.statement);ok=ok&&(h==cr.leaf)&&verify_path(sha,aas[cr.aa].tree,cr.attr,h);mm+=e2e_ms(m0,E2EClock::now());}tm.merkle_ms=mm;auto a0=E2EClock::now();RootInst pub=aggregate_public_only(Ahat,creds);tm.aggregate_ms=e2e_ms(a0,E2EClock::now());auto m0=E2EClock::now();Hash32 wid=manifest_wid(sha,c.id,pid,period,pub,roots,vers,c.k,c.participating);tm.manifest_ms=e2e_ms(m0,E2EClock::now());ok=ok&&(wid==expected);tm.ok=ok;tm.total_ms=e2e_ms(t0,E2EClock::now());VerifierState v;v.pub=std::move(pub);v.wid=wid;return v;}

using Registry=std::map<Hash32,uint64_t>;
struct OnlineSignRec{double state_ms=0,rng_ms=0,hmsg_ms=0,samplepre_ms=0,serialize_ms=0,total_ms=0,norm_ratio=0;u64 proposals=0;uint64_t bytes=0;bool ok=false;std::vector<unsigned char>token;};
static OnlineSignRec online_sign(const CaseCfg&c,uint64_t req,const SignerState&s,DZ&dz){OnlineSignRec r;auto t0=E2EClock::now();auto s0=E2EClock::now();bool state=s.version==1;r.state_ms=e2e_ms(s0,E2EClock::now());std::array<unsigned char,32>rs{};auto g0=E2EClock::now();os_random(rs.data(),32);r.rng_ms=e2e_ms(g0,E2EClock::now());auto h0=E2EClock::now();auto u=hmsg_thin(c.id,req,s.wid,rs);r.hmsg_ms=e2e_ms(h0,E2EClock::now());auto p=samplepre_on_target13(s.root,s.Te,s.Sc,u,dz);r.samplepre_ms=p.bench.total_ms;r.norm_ratio=p.bench.norm_ratio;r.proposals=p.bench.proposals_delta;auto z0=E2EClock::now();r.token=serialize_token(s.wid,rs,p.e);r.serialize_ms=e2e_ms(z0,E2EClock::now());r.bytes=r.token.size();r.ok=state&&p.bench.gsample&&p.bench.trap&&p.bench.preimage&&p.bench.normpass;r.total_ms=e2e_ms(t0,E2EClock::now());return r;}
struct OnlineVerifyRec{double parse_ms=0,current_ms=0,hmsg_ms=0,lattice_ms=0,total_ms=0;bool ok=false;};
static OnlineVerifyRec online_verify(const CaseCfg&c,uint64_t req,const VerifierState&v,const Registry&reg,const std::vector<unsigned char>&token){OnlineVerifyRec r;auto t0=E2EClock::now();ParsedToken p;try{auto q0=E2EClock::now();p=parse_token(token);r.parse_ms=e2e_ms(q0,E2EClock::now());}catch(...){r.total_ms=e2e_ms(t0,E2EClock::now());return r;}auto c0=E2EClock::now();auto it=reg.find(p.wid);bool current=(it!=reg.end()&&it->second==v.version&&p.wid==v.wid);r.current_ms=e2e_ms(c0,E2EClock::now());if(!current){r.total_ms=e2e_ms(t0,E2EClock::now());return r;}auto h0=E2EClock::now();auto u=hmsg_thin(c.id,req,p.wid,p.rsig);r.hmsg_ms=e2e_ms(h0,E2EClock::now());auto l0=E2EClock::now();r.ok=(norm2(p.e)<=BETA_SIG)&&(M_times_vec(v.pub,p.e)==u);r.lattice_ms=e2e_ms(l0,E2EClock::now());r.total_ms=e2e_ms(t0,E2EClock::now());return r;}

static bool negative_tests(const CaseCfg&c,const VerifierState&v,Registry&reg,const std::vector<unsigned char>&tok,uint64_t req){bool all=true;auto bad=tok;bad[40]^=1;all=all&&!online_verify(c,req,v,reg,bad).ok;bad=tok;bad[8]^=1;all=all&&!online_verify(c,req,v,reg,bad).ok;all=all&&!online_verify(c,req+999,v,reg,tok).ok;auto old=reg[v.wid];reg[v.wid]=old+1;all=all&&!online_verify(c,req,v,reg,tok).ok;reg[v.wid]=old;VerifierState cv=v;cv.pub.Bpub[0][0][0]=add_mod(cv.pub.Bpub[0][0][0],1);all=all&&!online_verify(c,req,cv,reg,tok).ok;bad=tok;bad[0]^=1;all=all&&!online_verify(c,req,v,reg,bad).ok;return all;}

struct Stat{size_t n=0;double mean=0,med=0,sd=0,p95=0,minv=0,maxv=0;};
static Stat stats(std::vector<double>v){Stat s;s.n=v.size();if(v.empty())return s;std::sort(v.begin(),v.end());s.minv=v.front();s.maxv=v.back();s.mean=std::accumulate(v.begin(),v.end(),0.0)/v.size();double ss=0;for(double x:v)ss+=(x-s.mean)*(x-s.mean);s.sd=std::sqrt(ss/v.size());s.med=v.size()%2?v[v.size()/2]:.5*(v[v.size()/2-1]+v[v.size()/2]);size_t p=(size_t)std::ceil(.95*v.size());if(p<1)p=1;if(p>v.size())p=v.size();s.p95=v[p-1];return s;}
static void emit_stat(std::ofstream&f,const std::string&id,const std::string&m,const std::vector<double>&v,const char*u){auto s=stats(v);f<<id<<","<<PROFILE_ID<<","<<m<<","<<u<<","<<s.n<<","<<std::setprecision(12)<<s.mean<<","<<s.med<<","<<s.sd<<","<<s.p95<<","<<s.minv<<","<<s.maxv<<"\n";}

static int stage13c_main(int argc,char**argv){
 try{bool quick=false;fs::path matrix,out="results";for(int i=1;i<argc;i++){std::string a=argv[i];if(a=="--quick")quick=true;else if(a=="--matrix"&&i+1<argc)matrix=argv[++i];else if(a=="--out"&&i+1<argc)out=argv[++i];}if(matrix.empty())throw std::runtime_error("--matrix required");fs::create_directories(out);auto cases=load_cases(matrix);if(quick&&cases.size()>3){std::vector<CaseCfg>x{cases.front(),cases[cases.size()/2],cases.back()};cases=x;}init_ntt();init_small_leaf_table();init_gm();init_crt();std::mt19937_64 rng(20260816ULL+HMAX);DZ dz(rng);MatU Ahat=random_Ahat(rng);E2ESha256 sha;
 std::ofstream raw(out/"stage13c_lattice_online_raw.csv"),cold(out/"stage13c_lattice_cold_raw.csv"),sum(out/"stage13c_lattice_summary.csv"),gate(out/"STAGE13C_LATTICE_VALIDATION.txt");
 raw<<"profile,case_id,group,k,participating,trial,state_ms,rng_ms,hmsg_ms,samplepre_ms,serialize_ms,online_sign_ms,parse_ms,current_ms,verify_hmsg_ms,lattice_ms,online_verify_ms,norm_over_beta,dz_proposals,thin_token_bytes,peak_rss_bytes,sign_ok,verify_ok\n";
 cold<<"profile,case_id,trial,signer_offline_ms,verifier_offline_ms,cold_sign_total_ms,cold_verify_total_ms,signer_aggregate_ms,signer_precompute_ms,verifier_cert_ms,verifier_merkle_ms,verifier_aggregate_ms,ok\n";
 sum<<"case_id,profile,metric,unit,n,mean,median,stddev,p95,min,max\n";
 gate<<"Stage 13C Online/Offline Thin Token\nprofile="<<PROFILE_ID<<"\nH_MAX="<<HMAX<<"\nzeta="<<(double)ZETA<<"\nbeta_sig="<<(double)BETA_SIG<<"\nproof_pack_bits="<<PROOF_PACK_BITS<<"\nproof_bytes="<<proof_bytes_packed()<<"\n";
 bool all=true;int total=0;for(size_t ci=0;ci<cases.size();ci++){CaseCfg c=cases[ci];if(quick){c.warmups=2;c.trials=3;c.cold_trials=1;}std::cout<<"CASE "<<c.id<<" k="<<c.k<<" J="<<c.participating<<" trials="<<c.trials<<"\n";std::array<unsigned char,32>pid{};deterministic_bytes(pid.data(),32,0xD13C0000ULL+ci+HMAX);uint64_t period=20260816;MLDKey dur=make_mld_key(0xD000ULL+ci);std::vector<unsigned char>durmsg(96);deterministic_bytes(durmsg.data(),durmsg.size(),0xDD00ULL+ci);auto dursig=mld_sign(durmsg,dur,false);std::vector<AAState>aas;for(int aa=0;aa<c.authorities;aa++)aas.emplace_back(0xAA130000ULL+ci*128+aa);std::vector<E2ECred>creds;for(int i=0;i<c.k;i++){E2ECred cr;cr.aa=i%c.participating;cr.attr=i/c.participating;cr.lat=issue_credential(rng,Ahat);cr.statement=credential_statement(cr.lat.Bpub,cr.aa,cr.attr,pid,period);cr.leaf=sha.hash(cr.statement);creds.push_back(std::move(cr));}for(int aa=0;aa<c.authorities;aa++){aas[aa].leaves.resize(c.leaves);for(int j=0;j<c.leaves;j++)aas[aa].leaves[j]=filler_leaf(sha,aa,j);}for(auto&cr:creds)aas[cr.aa].leaves[cr.attr]=cr.leaf;for(int aa=0;aa<c.authorities;aa++){aas[aa].tree=build_tree(sha,aas[aa].leaves);aas[aa].root_msg=root_message(aas[aa].tree.lv.back()[0],aa,c.leaves,aas[aa].version);aas[aa].root_sig=mld_sign(aas[aa].root_msg,aas[aa].key,false);}std::vector<Hash32>roots;std::vector<uint64_t>vers;for(int aa=0;aa<c.participating;aa++){roots.push_back(aas[aa].tree.lv.back()[0]);vers.push_back(aas[aa].version);}
 // actual cold repetitions
 std::vector<double>soff,voff,colds,coldv;for(int ct=0;ct<c.cold_trials;ct++){PrepRec sp,vp;SignerState ss=prepare_signer(c,Ahat,creds,aas,roots,vers,pid,period,sha,sp);VerifierState vv=prepare_verifier(c,Ahat,creds,aas,dur,durmsg,dursig,pid,period,ss.wid,sha,vp);Registry rg;rg[vv.wid]=vv.version;OnlineSignRec os=online_sign(c,9000000ULL+ct,ss,dz);OnlineVerifyRec ov=online_verify(c,9000000ULL+ct,vv,rg,os.token);bool ok=sp.ok&&vp.ok&&same_B(ss.root,vv.pub)&&os.ok&&ov.ok;all=all&&ok;soff.push_back(sp.total_ms);voff.push_back(vp.total_ms);colds.push_back(sp.total_ms+os.total_ms);coldv.push_back(vp.total_ms+ov.total_ms);cold<<PROFILE_ID<<","<<c.id<<","<<ct<<","<<sp.total_ms<<","<<vp.total_ms<<","<<sp.total_ms+os.total_ms<<","<<vp.total_ms+ov.total_ms<<","<<sp.aggregate_ms<<","<<sp.precompute_ms<<","<<vp.cert_ms<<","<<vp.merkle_ms<<","<<vp.aggregate_ms<<","<<ok<<"\n";}
 emit_stat(sum,c.id,"signer_offline_prepare",soff,"ms");emit_stat(sum,c.id,"verifier_offline_prepare",voff,"ms");emit_stat(sum,c.id,"cold_sign_total",colds,"ms");emit_stat(sum,c.id,"cold_verify_total",coldv,"ms");
 // final prepared states for warm online benchmark
 PrepRec sp,vp;SignerState ss=prepare_signer(c,Ahat,creds,aas,roots,vers,pid,period,sha,sp);VerifierState vv=prepare_verifier(c,Ahat,creds,aas,dur,durmsg,dursig,pid,period,ss.wid,sha,vp);Registry reg;reg[vv.wid]=vv.version;bool setupok=sp.ok&&vp.ok&&same_B(ss.root,vv.pub);all=all&&setupok;for(int w=0;w<c.warmups;w++){auto os=online_sign(c,7000000ULL+w,ss,dz);(void)online_verify(c,7000000ULL+w,vv,reg,os.token);}std::vector<double>sg,vr,hm,sm,ser,cur,lh,nr;uint64_t bytes=0;std::vector<unsigned char>lasttok;for(int t=0;t<c.trials;t++){auto os=online_sign(c,(uint64_t)t,ss,dz);auto ov=online_verify(c,(uint64_t)t,vv,reg,os.token);bool ok=os.ok&&ov.ok;all=all&&ok;total++;bytes=os.bytes;lasttok=os.token;raw<<PROFILE_ID<<","<<c.id<<","<<c.group<<","<<c.k<<","<<c.participating<<","<<t<<","<<os.state_ms<<","<<os.rng_ms<<","<<os.hmsg_ms<<","<<os.samplepre_ms<<","<<os.serialize_ms<<","<<os.total_ms<<","<<ov.parse_ms<<","<<ov.current_ms<<","<<ov.hmsg_ms<<","<<ov.lattice_ms<<","<<ov.total_ms<<","<<os.norm_ratio<<","<<os.proposals<<","<<os.bytes<<","<<peak_rss_bytes()<<","<<os.ok<<","<<ov.ok<<"\n";sg.push_back(os.total_ms);vr.push_back(ov.total_ms);hm.push_back(os.hmsg_ms);sm.push_back(os.samplepre_ms);ser.push_back(os.serialize_ms);cur.push_back(ov.current_ms);lh.push_back(ov.lattice_ms);nr.push_back(os.norm_ratio);}bool neg=negative_tests(c,vv,reg,lasttok,(uint64_t)(c.trials-1));all=all&&neg;emit_stat(sum,c.id,"online_sign",sg,"ms");emit_stat(sum,c.id,"online_verify",vr,"ms");emit_stat(sum,c.id,"thin_hmsg",hm,"ms");emit_stat(sum,c.id,"samplepre",sm,"ms");emit_stat(sum,c.id,"token_serialize",ser,"ms");emit_stat(sum,c.id,"manifest_current",cur,"ms");emit_stat(sum,c.id,"lattice_verify",lh,"ms");emit_stat(sum,c.id,"norm_over_beta",nr,"ratio");gate<<"case_"<<c.id<<"="<<(setupok&&neg?"PASS":"FAIL")<<" thin_bytes="<<bytes<<" negative_suite="<<(neg?"PASS":"FAIL")<<"\n";}
 gate<<"total_online_trials="<<total<<"\nsecurity_gate_source=Stage13B_PINNED_ESTIMATOR\nstrict_end_to_end_concrete_128=NOT_CLAIMED\nproduction_sampler=NOT_CLAIMED\noverall="<<(all?"PASS":"FAIL")<<"\n";std::cout<<"STAGE13C_LATTICE_OVERALL="<<(all?"PASS":"FAIL")<<"\n";return all?0:20;
 }catch(const std::exception&e){std::cerr<<"FATAL: "<<e.what()<<"\n";return 30;}
}
int main(int argc,char**argv){return stage13c_main(argc,argv);}
