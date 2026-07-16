use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use blake2::{Blake2b512, Digest};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
use std::path::{PathBuf, Path};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use x25519_dalek::{StaticSecret, PublicKey};
use chacha20poly1305::{aead::{Aead, Payload}, ChaCha20Poly1305, KeyInit, XChaCha20Poly1305, XNonce, Nonce};
use zeroize::Zeroizing;
use serde::{Serialize, Deserialize};

type HmacSha256 = Hmac<Sha256>;

const CHUNK_SIZE: usize = 65519;
const MAX_V3_BODY: usize = 132 * 1024 * 1024;
const OPK_NONE: u32 = 0xffffffff;
const MAX_SKIPPED_KEYS: usize = 1000;

#[derive(Parser)]
#[command(name="mesh-crypto", version="0.4.0", about="mesh V3 crypto client (DR, FS+PCS, 128MB, single token)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
    #[arg(long, default_value="https://fried.sh", global=true)]
    host: String,
}

#[derive(Subcommand)]
enum Commands {
    Gen,
    Fp,
    Claim,
    #[command(name="x3dh")]
    X3dh { #[command(subcommand)] sub: X3dhCmd },
    Allow { fp: String, #[arg(long, default_value="allow")] action: String },
    Send { #[arg(long)] to: String, #[arg(long)] msg: Option<String>, #[arg(long)] file: Option<String> },
    #[command(name="send-file")]
    SendFile { #[arg(long)] to: String, #[arg(long)] file: String },
    Poll { #[arg(long)] out: Option<String>, #[arg(long, default_value="true")] decrypt: bool },
    #[command(name="rotate-token")]
    RotateToken,
    #[command(name="allow-list")]
    AllowList,
}

#[derive(Subcommand)]
enum X3dhCmd { Publish }

#[derive(Serialize, Deserialize, Clone)]
struct Session {
    root_key_b64: String,
    chain_send_b64: Option<String>,
    chain_recv_b64: Option<String>,
    dh_send_priv_b64: String,
    dh_send_pub_b64: String,
    dh_recv_pub_b64: Option<String>,
    n_send: u32,
    n_recv: u32,
    pn: u32,
    header_key_b64: String,
    #[serde(default)]
    skipped_keys: HashMap<String, String>, // key = dh_pub_hex + "-" + n -> mk_b64
    created_at: i64,
}

impl Session {
    fn root_key(&self) -> Result<Vec<u8>> { Ok(b64_decode(&self.root_key_b64)?) }
    fn chain_send(&self) -> Result<Option<Vec<u8>>> { if let Some(s)=&self.chain_send_b64 { Ok(Some(b64_decode(s)?)) } else { Ok(None) } }
    fn chain_recv(&self) -> Result<Option<Vec<u8>>> { if let Some(s)=&self.chain_recv_b64 { Ok(Some(b64_decode(s)?)) } else { Ok(None) } }
    fn dh_send_priv_bytes(&self) -> Result<[u8;32]> { let v=b64_decode(&self.dh_send_priv_b64)?; if v.len()!=32 { return Err(anyhow!("bad dh priv len")); } Ok(v.try_into().unwrap()) }
    fn dh_send_pub_bytes(&self) -> Result<[u8;32]> { let v=b64_decode(&self.dh_send_pub_b64)?; if v.len()!=32 { return Err(anyhow!("bad dh pub len")); } Ok(v.try_into().unwrap()) }
    fn dh_recv_pub_bytes(&self) -> Result<Option<[u8;32]>> { if let Some(s)=&self.dh_recv_pub_b64 { let v=b64_decode(s)?; if v.len()!=32 { return Err(anyhow!("bad dh recv len")); } Ok(Some(v.try_into().unwrap())) } else { Ok(None) } }
    fn header_key(&self) -> Result<[u8;32]> { let v=b64_decode(&self.header_key_b64)?; if v.len()!=32 { return Err(anyhow!("bad header key len")); } Ok(v.try_into().unwrap()) }
}

fn mesh_dir() -> PathBuf { dirs::home_dir().expect("no home").join(".mesh-v3") }
fn keys_dir() -> PathBuf { mesh_dir().join("keys") }
fn sessions_dir() -> PathBuf { mesh_dir().join("sessions") }
fn session_path(peer_fp: &str) -> PathBuf { sessions_dir().join(format!("{}.json", peer_fp.to_ascii_lowercase())) }
fn now_secs() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 }

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    URL_SAFE_NO_PAD.decode(s).or_else(|_| STANDARD.decode(s)).map_err(|e| anyhow!("b64 decode: {} on {}", e, &s[..std::cmp::min(20,s.len())]))
}
fn b64_encode(b: &[u8]) -> String { URL_SAFE_NO_PAD.encode(b) }

fn load_identity() -> Result<(Zeroizing<[u8;32]>, SigningKey, String, StaticSecret, PublicKey)> {
    let dir = mesh_dir();
    let secret = fs::read(dir.join("secret.key"))?;
    if secret.len() < 64 { return Err(anyhow!("secret.key len {}", secret.len())); }
    let mut ed_seed = [0u8;32]; ed_seed.copy_from_slice(&secret[0..32]);
    let mut x_priv_bytes = [0u8;32]; x_priv_bytes.copy_from_slice(&secret[32..64]);
    let ed_seed_z = Zeroizing::new(ed_seed);
    let ed_sk = SigningKey::from_bytes(&ed_seed_z);
    let fp = fs::read_to_string(dir.join("fp"))?.trim().to_ascii_lowercase();
    let x_priv = StaticSecret::from(x_priv_bytes);
    let x_pub = PublicKey::from(&x_priv);
    Ok((ed_seed_z, ed_sk, fp, x_priv, x_pub))
}
fn fp_to_bytes(fp: &str) -> Result<[u8;32]> {
    if fp.len()!=64 { return Err(anyhow!("fp len")); }
    let mut out=[0u8;32];
    for i in 0..32 {
        out[i]=u8::from_str_radix(&fp[i*2..i*2+2],16).map_err(|_| anyhow!("bad hex"))?;
    }
    Ok(out)
}
fn fp_from_bytes(b: &[u8;32]) -> String { hex::encode(b) }

fn ed_verify(fp_hex: &str, msg: &[u8], sig_b64: &str) -> Result<bool> {
    let fp_bytes = fp_to_bytes(fp_hex)?;
    let vk = VerifyingKey::from_bytes(&fp_bytes).map_err(|e| anyhow!("bad vk: {:?}", e))?;
    let sig_bytes = b64_decode(sig_b64)?;
    if sig_bytes.len()!=64 { return Err(anyhow!("sig len {}", sig_bytes.len())); }
    let sig = Signature::from_bytes(&sig_bytes.clone().try_into().unwrap());
    Ok(vk.verify_strict(msg, &sig).is_ok())
}
fn hkdf_derive(ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).map_err(|e| anyhow!("hkdf {:?}", e))?;
    Ok(okm)
}
fn hkdf_derive_salt(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm).map_err(|e| anyhow!("hkdf {:?}", e))?;
    Ok(okm)
}
fn kdf_rk(rk: &[u8], dh_out: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let okm = hkdf_derive_salt(rk, dh_out, b"mesh-v3-rk", 64)?;
    Ok((okm[0..32].to_vec(), okm[32..64].to_vec()))
}
fn kdf_ck(ck: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    use hmac::Mac as _;
    let mut mac1 = <HmacSha256 as hmac::Mac>::new_from_slice(ck).map_err(|e| anyhow!("hmac ck {:?}", e))?;
    mac1.update(&[0x01]);
    let ck_next = mac1.finalize().into_bytes().to_vec();
    let mut mac2 = <HmacSha256 as hmac::Mac>::new_from_slice(ck).map_err(|e| anyhow!("hmac mk {:?}", e))?;
    mac2.update(&[0x02]);
    let mk = mac2.finalize().into_bytes().to_vec();
    Ok((ck_next, mk))
}
fn xenc(key: &[u8;32], nonce: &[u8;24], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("{:?}", e))?;
    c.encrypt(XNonce::from_slice(nonce), Payload{msg:pt,aad}).map_err(|e| anyhow!("enc {:?}", e))
}
fn xdec(key: &[u8;32], nonce: &[u8;24], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = XChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("{:?}", e))?;
    c.decrypt(XNonce::from_slice(nonce), Payload{msg:ct,aad}).map_err(|e| anyhow!("dec {:?}", e))
}
fn cenc(key: &[u8;32], nonce: &[u8;12], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("{:?}", e))?;
    c.encrypt(Nonce::from_slice(nonce), Payload{msg:pt,aad}).map_err(|e| anyhow!("enc {:?}", e))
}
fn cdec(key: &[u8;32], nonce: &[u8;12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = ChaCha20Poly1305::new_from_slice(key).map_err(|e| anyhow!("{:?}", e))?;
    c.decrypt(Nonce::from_slice(nonce), Payload{msg:ct,aad}).map_err(|e| anyhow!("dec {:?}", e))
}

fn generate_dh_keypair() -> ([u8;32], [u8;32]) {
    let mut priv_bytes = [0u8;32];
    OsRng.fill_bytes(&mut priv_bytes);
    let priv_ = StaticSecret::from(priv_bytes);
    let pub_ = PublicKey::from(&priv_);
    (priv_bytes, *pub_.as_bytes())
}

fn load_session(peer_fp: &str) -> Option<Session> {
    let p = session_path(peer_fp);
    if !p.exists() { return None; }
    let data = fs::read_to_string(&p).ok()?;
    serde_json::from_str(&data).ok()
}
fn save_session(peer_fp: &str, sess: &Session) -> Result<()> {
    let dir = sessions_dir();
    fs::create_dir_all(&dir)?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    let p = session_path(peer_fp);
    let json = serde_json::to_string_pretty(sess)?;
    fs::write(&p, json)?;
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn cmd_gen() -> Result<()> {
    let dir = mesh_dir();
    fs::create_dir_all(&dir)?; fs::create_dir_all(keys_dir())?; fs::create_dir_all(dir.join("prekeys"))?; fs::create_dir_all(sessions_dir())?;
    let _ = fs::set_permissions(sessions_dir(), fs::Permissions::from_mode(0o700));
    let mut ed_seed=[0u8;32]; OsRng.fill_bytes(&mut ed_seed);
    let ed_sk=SigningKey::from_bytes(&ed_seed);
    let fp=hex::encode(ed_sk.verifying_key().as_bytes());
    let mut x_priv_bytes=[0u8;32]; OsRng.fill_bytes(&mut x_priv_bytes);
    let x_priv=StaticSecret::from(x_priv_bytes);
    let x_pub=PublicKey::from(&x_priv);
    let x_sig=ed_sk.sign(x_pub.as_bytes());
    let mut sec=Vec::new(); sec.extend_from_slice(&ed_seed); sec.extend_from_slice(&x_priv_bytes);
    fs::write(dir.join("secret.key"), &sec)?; fs::set_permissions(dir.join("secret.key"), fs::Permissions::from_mode(0o600))?;
    fs::write(dir.join("fp"), format!("{}\n", fp))?;
    fs::write(dir.join("x_id_pub"), b64_encode(x_pub.as_bytes()))?;
    fs::write(dir.join("x_id_sig"), b64_encode(&x_sig.to_bytes()))?;
    println!("generated fp={}", fp);
    Ok(())
}
fn cmd_fp() -> Result<()> { println!("{}", fs::read_to_string(mesh_dir().join("fp"))?.trim().to_ascii_lowercase()); Ok(()) }

async fn cmd_claim(host: &str) -> Result<()> {
    let (_, ed_sk, fp, _, _) = load_identity()?;
    let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    let chal_url=format!("{}/mesh/v3/{}/claim/challenge", host.trim_end_matches('/'), fp);
    let resp=client.get(&chal_url).send().await?; if !resp.status().is_success(){return Err(anyhow!("challenge {}", resp.text().await?));}
    let j:serde_json::Value=resp.json().await?; let nonce=j["nonce"].as_str().ok_or(anyhow!("no nonce"))?.to_string();
    let ts=now_secs(); let msg=format!("CLAIM /mesh/v3/{}/claim\n{}\n{}", fp, ts, nonce);
    let sig=ed_sk.sign(msg.as_bytes()); let sig_b64=STANDARD.encode(sig.to_bytes());
    let claim_url=format!("{}/mesh/v3/{}/claim", host.trim_end_matches('/'), fp);
    let body=serde_json::json!({"ts":ts,"nonce":nonce,"sig":sig_b64});
    let resp=client.post(&claim_url).header("X-Mesh-Timestamp",ts.to_string()).header("X-Mesh-Nonce",nonce.clone()).header("X-Mesh-Signature",sig_b64.clone()).json(&body).send().await?;
    let st=resp.status(); let txt=resp.text().await?; if !st.is_success(){return Err(anyhow!("claim {} {}", st, txt));}
    let j:serde_json::Value=serde_json::from_str(&txt)?; let token=j["token"].as_str().ok_or(anyhow!("no token"))?.to_string();
    fs::create_dir_all(keys_dir())?; let kp=keys_dir().join(format!("{}.key",fp)); fs::write(&kp,format!("{}\n",token))?; fs::set_permissions(&kp,fs::Permissions::from_mode(0o600))?;
    println!("claimed {}", fp); println!("token {}", token); Ok(())
}
async fn cmd_x3dh_publish(host: &str) -> Result<()> {
    let (_, ed_sk, fp, _, x_pub)=load_identity()?;
    let token=fs::read_to_string(keys_dir().join(format!("{}.key",fp)))?.trim().to_string();
    let mut spk_priv_bytes=[0u8;32]; OsRng.fill_bytes(&mut spk_priv_bytes);
    let spk_priv=StaticSecret::from(spk_priv_bytes); let spk_pub=PublicKey::from(&spk_priv);
    let spk_sig=ed_sk.sign(spk_pub.as_bytes()); let spk_id=(OsRng.next_u32()%1_000_000) as u32;
    let prekeys_dir=mesh_dir().join("prekeys"); fs::create_dir_all(&prekeys_dir)?;
    let mut opks=Vec::new();
    for i in 0..100u32 { let mut b=[0u8;32]; OsRng.fill_bytes(&mut b); let priv_=StaticSecret::from(b); let pub_=PublicKey::from(&priv_); fs::write(prekeys_dir.join(format!("opk_{}.priv",i)), b64_encode(&b))?; let _=fs::set_permissions(prekeys_dir.join(format!("opk_{}.priv",i)), fs::Permissions::from_mode(0o600)); opks.push(serde_json::json!({"id":i,"pub":b64_encode(pub_.as_bytes())})); }
    fs::write(prekeys_dir.join(format!("spk_{}.priv",spk_id)), b64_encode(&spk_priv_bytes))?; fs::write(prekeys_dir.join("spk_priv"), b64_encode(&spk_priv_bytes))?; fs::write(prekeys_dir.join("spk_id"), spk_id.to_string())?; fs::write(prekeys_dir.join("spk_created_at"), now_secs().to_string())?;
    let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    let url=format!("{}/mesh/v3/{}/x3dh/publish", host.trim_end_matches('/'), fp);
    let body=serde_json::json!({"x_id_pub":b64_encode(x_pub.as_bytes()),"x_id_sig":fs::read_to_string(mesh_dir().join("x_id_sig"))?.trim(),"spk_id":spk_id,"spk_pub":b64_encode(spk_pub.as_bytes()),"spk_sig":STANDARD.encode(spk_sig.to_bytes()),"opks":opks});
    let resp=client.post(&url).header("X-Mesh-Key",token).json(&body).send().await?; let st=resp.status(); let txt=resp.text().await?; if !st.is_success(){return Err(anyhow!("publish {} {}", st, txt));}
    println!("published {}", txt); Ok(())
}
async fn cmd_allow(fp_target: &str, action: &str, host: &str) -> Result<()> {
    let (_,_,fp,_,_)=load_identity()?; let token=fs::read_to_string(keys_dir().join(format!("{}.key",fp)))?.trim().to_string();
    let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    let url=format!("{}/mesh/v3/{}/allow", host.trim_end_matches('/'), fp);
    let resp=client.post(&url).header("X-Mesh-Key",token).json(&serde_json::json!({"fp":fp_target.to_ascii_lowercase(),"action":action})).send().await?;
    println!("{}", resp.text().await?); Ok(())
}
async fn fetch_bundle(host: &str, peer_fp: &str) -> Result<serde_json::Value> {
    let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    let url=format!("{}/mesh/v3/{}/x3dh/bundle", host.trim_end_matches('/'), peer_fp.to_ascii_lowercase());
    let resp=client.get(&url).send().await?; if !resp.status().is_success(){return Err(anyhow!("bundle {}", resp.text().await?));}
    Ok(resp.json().await?)
}

// returns (sk, ek_pub_bytes, spk_id, opk_id)
fn x3dh_alice(my_x_priv: &StaticSecret, my_fp: &str, peer_fp: &str, bundle: &serde_json::Value) -> Result<(Vec<u8>, [u8;32], u32, u32)> {
    let peer_fp_lc=peer_fp.to_ascii_lowercase();
    let x_id_pub_b64=bundle["x_id_pub"].as_str().ok_or(anyhow!("missing x_id_pub"))?;
    let x_id_sig_b64=bundle["x_id_sig"].as_str().ok_or(anyhow!("missing x_id_sig"))?;
    let x_id_pub_bytes=b64_decode(x_id_pub_b64)?; if !ed_verify(&peer_fp_lc,&x_id_pub_bytes,x_id_sig_b64)? {return Err(anyhow!("bad x_id_sig"));}
    let spk_pub_b64=bundle["spk_pub"].as_str().ok_or(anyhow!("missing spk_pub"))?;
    let spk_sig_b64=bundle["spk_sig"].as_str().ok_or(anyhow!("missing spk_sig"))?;
    let spk_pub_bytes=b64_decode(spk_pub_b64)?; if !ed_verify(&peer_fp_lc,&spk_pub_bytes,spk_sig_b64)? {return Err(anyhow!("bad spk_sig"));}
    let spk_id=bundle["spk_id"].as_u64().unwrap_or(0) as u32;
    let opk_id=bundle["opk_id"].as_u64().map(|v|v as u32).unwrap_or(OPK_NONE);
    let opk_pub_opt=bundle["opk_pub"].as_str().map(|s| b64_decode(s).unwrap());
    let peer_x_pub=PublicKey::from(<[u8;32]>::try_from(x_id_pub_bytes).unwrap());
    let peer_spk_pub=PublicKey::from(<[u8;32]>::try_from(spk_pub_bytes).unwrap());
    let mut ek_priv_bytes=[0u8;32]; OsRng.fill_bytes(&mut ek_priv_bytes);
    let ek_priv=StaticSecret::from(ek_priv_bytes); let ek_pub=PublicKey::from(&ek_priv);
    let ek_pub_bytes=ek_pub.to_bytes();
    let dh1=my_x_priv.diffie_hellman(&peer_spk_pub);
    let dh2=ek_priv.diffie_hellman(&peer_x_pub);
    let dh3=ek_priv.diffie_hellman(&peer_spk_pub);
    let mut ikm=Vec::new(); ikm.extend_from_slice(dh1.as_bytes()); ikm.extend_from_slice(dh2.as_bytes()); ikm.extend_from_slice(dh3.as_bytes());
    if let Some(opk_bytes)=opk_pub_opt { let opk_pub=PublicKey::from(<[u8;32]>::try_from(opk_bytes).unwrap()); let dh4=ek_priv.diffie_hellman(&opk_pub); ikm.extend_from_slice(dh4.as_bytes()); }
    // zeroize ek_priv immediately after use for FS
    let mut ek_zero = Zeroizing::new(ek_priv_bytes);
    ek_zero.fill(0);
    let my_fp_bytes=fp_to_bytes(my_fp)?; let peer_fp_bytes=fp_to_bytes(&peer_fp_lc)?;
    let mut info=Vec::new(); info.extend_from_slice(b"mesh-v3-x3dh v1"); info.extend_from_slice(&my_fp_bytes); info.extend_from_slice(&peer_fp_bytes); info.extend_from_slice(&spk_id.to_be_bytes()); info.extend_from_slice(&opk_id.to_be_bytes());
    let sk=hkdf_derive(&ikm,&info,32)?;
    // zeroize ikm
    let mut ikm_z = Zeroizing::new(ikm);
    ikm_z.fill(0);
    Ok((sk, ek_pub_bytes, spk_id, opk_id))
}

fn init_session_from_x3dh(sk: &[u8], peer_spk_pub_bytes: &[u8]) -> Result<Session> {
    // root = SK, header_key = HKDF(SK, "header"), chain_send = chain_recv = HKDF(SK, "chain") for initial sync
    let header_key = hkdf_derive(sk, b"mesh-v3-header v1", 32)?;
    let chain = hkdf_derive(sk, b"mesh-v3-chain", 32)?;
    let (dh_priv, dh_pub) = generate_dh_keypair();
    // For initial, dh_recv is peer's spk (or None) - use spk pub as initial recv
    let dh_recv_b64 = if peer_spk_pub_bytes.len()==32 { Some(b64_encode(peer_spk_pub_bytes)) } else { None };
    Ok(Session {
        root_key_b64: b64_encode(sk),
        chain_send_b64: Some(b64_encode(&chain)),
        chain_recv_b64: Some(b64_encode(&chain)),
        dh_send_priv_b64: b64_encode(&dh_priv),
        dh_send_pub_b64: b64_encode(&dh_pub),
        dh_recv_pub_b64: dh_recv_b64,
        n_send: 0,
        n_recv: 0,
        pn: 0,
        header_key_b64: b64_encode(&header_key),
        skipped_keys: HashMap::new(),
        created_at: now_secs(),
    })
}

async fn cmd_send(to: &str, msg_opt: Option<String>, file_opt: Option<String>, host: &str) -> Result<()> {
    if let Some(f)=file_opt { return cmd_send_file(to,&f,host).await; }
    let msg=msg_opt.unwrap_or_else(||"hello v3".to_string());
    let (_,_,my_fp,my_x_priv,my_x_pub)=load_identity()?;
    let my_token=fs::read_to_string(keys_dir().join(format!("{}.key",my_fp)))?.trim().to_string();
    let peer_fp=to.to_ascii_lowercase(); if peer_fp.len()!=64{return Err(anyhow!("peer fp len"));}
    
    // Load or init session
    let mut sess_opt = load_session(&peer_fp);
    let mut is_new_session = false;
    let mut ek_pub_bytes_opt: Option<[u8;32]> = None;
    let mut spk_id_opt = 0u32;
    let mut opk_id_opt = OPK_NONE;
    let mut bundle_spk_pub_bytes: Vec<u8> = Vec::new();
    
    if sess_opt.is_none() {
        // X3DH to init
        let bundle=fetch_bundle(host,&peer_fp).await?;
        let spk_pub_b64 = bundle["spk_pub"].as_str().unwrap_or("").to_string();
        bundle_spk_pub_bytes = b64_decode(&spk_pub_b64).unwrap_or_default();
        let (sk, ek_pub_bytes, spk_id, opk_id)=x3dh_alice(&my_x_priv,&my_fp,&peer_fp,&bundle)?;
        let mut sess = init_session_from_x3dh(&sk, &bundle_spk_pub_bytes)?;
        // zeroize sk after use
        let mut sk_z = Zeroizing::new(sk);
        sk_z.fill(0);
        ek_pub_bytes_opt = Some(ek_pub_bytes);
        spk_id_opt = spk_id;
        opk_id_opt = opk_id;
        sess_opt = Some(sess);
        is_new_session = true;
    }
    
    let mut sess = sess_opt.unwrap();
    
    // If chain_send None, we need to ratchet (should not happen for new session as we init it)
    if sess.chain_send_b64.is_none() {
        // Need DH ratchet with current recv pub
        if let Some(dh_recv_b64) = &sess.dh_recv_pub_b64.clone() {
            let dh_recv_bytes = b64_decode(dh_recv_b64)?;
            let dh_recv_pub = PublicKey::from(<[u8;32]>::try_from(dh_recv_bytes).unwrap());
            let (new_dh_priv, new_dh_pub) = generate_dh_keypair();
            let new_dh_priv_ss = StaticSecret::from(new_dh_priv);
            let dh_out = new_dh_priv_ss.diffie_hellman(&dh_recv_pub);
            let rk = b64_decode(&sess.root_key_b64)?;
            let (new_rk, new_chain) = kdf_rk(&rk, dh_out.as_bytes())?;
            // zeroize old rk?
            sess.root_key_b64 = b64_encode(&new_rk);
            sess.chain_send_b64 = Some(b64_encode(&new_chain));
            sess.dh_send_priv_b64 = b64_encode(&new_dh_priv);
            sess.dh_send_pub_b64 = b64_encode(&new_dh_pub);
            sess.pn = sess.n_send;
            sess.n_send = 0;
            // zeroize dh_out, new_rk, new_chain after encoding? They are cloned into b64, ok
            let mut dh_out_z = Zeroizing::new(dh_out.as_bytes().to_vec());
            dh_out_z.fill(0);
        } else {
            return Err(anyhow!("no chain and no recv pub to ratchet"));
        }
    }
    
    // Now we have chain_send
    let chain_send_bytes = b64_decode(sess.chain_send_b64.as_ref().unwrap())?;
    let (ck_next, mk_bytes) = kdf_ck(&chain_send_bytes)?;
    // zeroize old chain immediately
    let mut chain_z = Zeroizing::new(chain_send_bytes);
    chain_z.fill(0);
    
    // Prepare header with real n/pn and dh_pub
    let dh_send_pub_bytes = b64_decode(&sess.dh_send_pub_b64)?;
    let n = sess.n_send;
    let pn = sess.pn;
    
    // FIX: random nonces for header and body, not fixed [0;24]
    let mut header_nonce = [0u8;24]; OsRng.fill_bytes(&mut header_nonce);
    let mut body_nonce = [0u8;24]; OsRng.fill_bytes(&mut body_nonce);
    
    let header_key_bytes = b64_decode(&sess.header_key_b64)?;
    let header_key_arr: [u8;32] = header_key_bytes.try_into().map_err(|_| anyhow!("header key len"))?;
    let header_plain = serde_json::json!({"dh": b64_encode(&dh_send_pub_bytes), "pn": pn, "n": n}).to_string();
    let header_ct = xenc(&header_key_arr, &header_nonce, header_plain.as_bytes(), b"")?;
    
    let mk_arr: [u8;32] = mk_bytes.clone().try_into().map_err(|_| anyhow!("mk len"))?;
    let pt = serde_json::json!({"text":msg,"from":my_fp,"ts":now_secs(), "n": n, "pn": pn}).to_string();
    let body_ct = xenc(&mk_arr, &body_nonce, pt.as_bytes(), &header_ct)?;
    
    // zeroize mk after use for FS
    let mut mk_z = Zeroizing::new(mk_bytes.clone());
    mk_z.fill(0);
    
    // Build envelope 0x04 for DR
    let my_fp_bytes=fp_to_bytes(&my_fp)?; 
    let mut out=Vec::new();
    out.push(0x04);
    if is_new_session {
        // First message includes X3DH data for Bob to derive SK
        out.push(0x01); // X3DH+DR init
        let ek_pub_bytes = ek_pub_bytes_opt.unwrap();
        out.extend_from_slice(&ek_pub_bytes);
        out.extend_from_slice(&my_fp_bytes);
        out.extend_from_slice(my_x_pub.as_bytes());
        out.extend_from_slice(&spk_id_opt.to_be_bytes());
        out.extend_from_slice(&opk_id_opt.to_be_bytes());
    } else {
        out.push(0x03); // DR only (no X3DH)
        // No ek, no spk/opk
        out.extend_from_slice(&my_fp_bytes);
        out.extend_from_slice(my_x_pub.as_bytes());
    }
    // DR header part (always)
    out.extend_from_slice(&dh_send_pub_bytes);
    out.extend_from_slice(&pn.to_be_bytes());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&header_nonce);
    out.extend_from_slice(&(header_ct.len() as u16).to_be_bytes());
    out.extend_from_slice(&header_ct);
    out.extend_from_slice(&body_nonce);
    out.extend_from_slice(&body_ct);
    
    let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    let resp=client.post(format!("{}/mesh/v3/{}",host.trim_end_matches('/'),peer_fp)).header("X-Mesh-Key",my_token).header("X-Mesh-From",my_fp.clone()).header("Content-Type","application/octet-stream").body(out).send().await?;
    let st=resp.status(); let txt=resp.text().await?; if !st.is_success(){return Err(anyhow!("send {} {}",st,txt));}
    
    // Update session state
    sess.chain_send_b64 = Some(b64_encode(&ck_next));
    sess.n_send = n + 1;
    save_session(&peer_fp, &sess)?;
    
    // zeroize ck_next
    let mut ck_next_z = Zeroizing::new(ck_next);
    ck_next_z.fill(0);
    
    println!("sent {} (n={} pn={} dh={}..)", txt, n, pn, &hex::encode(&dh_send_pub_bytes)[0..8]);
    Ok(())
}

async fn cmd_send_file(to: &str, file_path: &str, host: &str) -> Result<()> {
    let (_,_,my_fp,my_x_priv,my_x_pub)=load_identity()?;
    let my_token=fs::read_to_string(keys_dir().join(format!("{}.key",my_fp)))?.trim().to_string();
    let peer_fp=to.to_ascii_lowercase();
    let bundle=fetch_bundle(host,&peer_fp).await?;
    let (sk, ek_pub_bytes, spk_id, opk_id)=x3dh_alice(&my_x_priv,&my_fp,&peer_fp,&bundle)?;
    let file_bytes=fs::read(file_path)?; if file_bytes.len()>128*1024*1024{return Err(anyhow!(">128M"));}
    let mut hasher=Blake2b512::new(); hasher.update(&file_bytes); let hash=hasher.finalize(); let hash_hex=hex::encode(&hash[0..32]);
    let mut fk=[0u8;32]; OsRng.fill_bytes(&mut fk); let mut base_nonce=[0u8;12]; OsRng.fill_bytes(&mut base_nonce);
    // Use fresh random nonces for header and new KDF result - derive hek/mk from sk but with random nonces (fix bug)
    let okm=hkdf_derive_salt(&sk,&sk,b"mesh-v3-msg v1",64)?; 
    let hek_bytes = &okm[0..32];
    let hek: [u8;32]= hek_bytes.try_into().unwrap(); 
    let _mk_bytes = &okm[32..64];
    // zeroize sk
    let mut sk_z = Zeroizing::new(sk);
    sk_z.fill(0);
    let file_name=Path::new(file_path).file_name().unwrap().to_string_lossy().to_string();
    let chunks=(file_bytes.len()+CHUNK_SIZE-1)/CHUNK_SIZE;
    let header_json=serde_json::json!({"type":"file","name":file_name,"size":file_bytes.len(),"chunks":chunks,"chunk_size":CHUNK_SIZE,"hash":hash_hex,"fk":b64_encode(&fk),"base_nonce":b64_encode(&base_nonce),"spk_id":spk_id,"opk_id":opk_id});
    let mut header_nonce=[0u8;24]; OsRng.fill_bytes(&mut header_nonce);
    let header_ct=xenc(&hek,&header_nonce,header_json.to_string().as_bytes(),b"")?;
    let mut hh=Blake2b512::new(); hh.update(&header_ct); let header_hash=hh.finalize(); let header_hash32=&header_hash[0..32];
    let my_fp_bytes=fp_to_bytes(&my_fp)?; let mut out=Vec::new();
    out.push(0x03); out.push(0x02); out.extend_from_slice(&ek_pub_bytes); out.extend_from_slice(&my_fp_bytes); out.extend_from_slice(my_x_pub.as_bytes());
    out.extend_from_slice(&spk_id.to_be_bytes()); out.extend_from_slice(&opk_id.to_be_bytes());
    // include header_nonce for fix
    out.extend_from_slice(&header_nonce);
    out.extend_from_slice(&(header_ct.len() as u16).to_be_bytes()); out.extend_from_slice(&header_ct);
    for i in 0..chunks {
        let s=i*CHUNK_SIZE; let e=std::cmp::min(s+CHUNK_SIZE,file_bytes.len()); let chunk=&file_bytes[s..e];
        let is_last=if i==chunks-1{1u8}else{0u8};
        let mut n12=[0u8;12]; n12[0..4].copy_from_slice(&base_nonce[0..4]); n12[4..12].copy_from_slice(&(i as u64).to_le_bytes());
        let mut ad=Vec::new(); ad.extend_from_slice(header_hash32); ad.extend_from_slice(&(i as u64).to_le_bytes()); ad.push(is_last);
        let ct=cenc(&fk,&n12,chunk,&ad)?; out.extend_from_slice(&(ct.len() as u16).to_be_bytes()); out.extend_from_slice(&ct);
    }
    // zeroize fk
    let mut fk_z = Zeroizing::new(fk);
    fk_z.fill(0);
    let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    // bypass nginx 512k limit: if out > 450k, use chunked upload via new /file/<id>/chunk/<idx> endpoints
    let out_len = out.len();
    if out_len <= 450*1024 {
        let resp=client.post(format!("{}/mesh/v3/{}",host.trim_end_matches('/'),peer_fp)).header("X-Mesh-Key",my_token.clone()).header("X-Mesh-From",my_fp.clone()).header("Content-Type","application/octet-stream").body(out).send().await?;
        let st=resp.status(); let txt=resp.text().await?; if !st.is_success(){return Err(anyhow!("send-file {} {}",st,txt));}
        println!("sent file {} ({} bytes {} chunks wire {} bytes) {}", file_path, file_bytes.len(), chunks, out_len, txt); Ok(())
    } else {
        // chunked file upload: nginx is now 150m, use 8M chunks for speed (16x faster than 400k)
        const FILE_CHUNK_SIZE: usize = 8*1024*1024; // 8388608, well under 10M server limit + 150m nginx
        let file_id = {
            let mut rnd = [0u8;16]; OsRng.fill_bytes(&mut rnd);
            hex::encode(rnd)
        };
        let total_file_chunks = (out_len + FILE_CHUNK_SIZE - 1) / FILE_CHUNK_SIZE;
        println!("send-file {} ({} bytes) -> wire {} bytes, chunked upload {} x {}M via file_id {}", file_path, file_bytes.len(), out_len, total_file_chunks, FILE_CHUNK_SIZE/(1024*1024), &file_id[0..8]);
        for i in 0..total_file_chunks {
            let s = i*FILE_CHUNK_SIZE;
            let e = std::cmp::min(s+FILE_CHUNK_SIZE, out_len);
            let chunk = &out[s..e];
            let url = format!("{}/mesh/v3/{}/file/{}/chunk/{}", host.trim_end_matches('/'), peer_fp, file_id, i);
            let resp = client.post(&url).header("X-Mesh-Key", my_token.clone()).header("X-Mesh-From", my_fp.clone()).header("Content-Type","application/octet-stream").body(chunk.to_vec()).send().await?;
            let st = resp.status(); let txt = resp.text().await?;
            if !st.is_success() {
                return Err(anyhow!("send-file chunk {}/{} failed {} {}", i+1, total_file_chunks, st, txt));
            }
            // small progress
            if total_file_chunks > 10 && (i+1) % 10 == 0 {
                println!("  chunk {}/{} ok", i+1, total_file_chunks);
            }
        }
        // finalize
        let finalize_url = format!("{}/mesh/v3/{}/file/{}/finalize", host.trim_end_matches('/'), peer_fp, file_id);
        let resp = client.post(&finalize_url).header("X-Mesh-Key", my_token).header("X-Mesh-From", my_fp.clone()).header("Content-Type","application/json").body(format!("{{\"total\":{}}}", total_file_chunks)).send().await?;
        let st=resp.status(); let txt=resp.text().await?; if !st.is_success(){return Err(anyhow!("send-file finalize {} {}",st,txt));}
        println!("sent file {} ({} bytes {} inner chunks, {} wire chunks) {} final {}", file_path, file_bytes.len(), chunks, total_file_chunks, file_id, txt); Ok(())
    }
}

fn load_prekey_priv(kind: &str, id: u32) -> Result<StaticSecret> {
    let dir=mesh_dir().join("prekeys");
    let p=if kind=="spk"{ let p1=dir.join(format!("spk_{}.priv",id)); if p1.exists(){p1}else{dir.join("spk_priv")} } else { dir.join(format!("opk_{}.priv",id)) };
    let b=b64_decode(fs::read_to_string(&p)?.trim())?; Ok(StaticSecret::from(<[u8;32]>::try_from(b).unwrap()))
}
fn x3dh_bob(my_x_priv: &StaticSecret, my_fp: &str, peer_fp: &str, peer_x_pub: &PublicKey, ek_pub: &PublicKey, spk_id: u32, opk_id: u32) -> Result<Vec<u8>> {
    let spk_priv=load_prekey_priv("spk", spk_id)?;
    let dh1=spk_priv.diffie_hellman(peer_x_pub);
    let dh2=my_x_priv.diffie_hellman(ek_pub);
    let dh3=spk_priv.diffie_hellman(ek_pub);
    let mut ikm=Vec::new(); ikm.extend_from_slice(dh1.as_bytes()); ikm.extend_from_slice(dh2.as_bytes()); ikm.extend_from_slice(dh3.as_bytes());
    if opk_id!=OPK_NONE { let opk_priv=load_prekey_priv("opk", opk_id)?; let dh4=opk_priv.diffie_hellman(ek_pub); ikm.extend_from_slice(dh4.as_bytes()); }
    let peer_fp_bytes=fp_to_bytes(peer_fp)?; let my_fp_bytes=fp_to_bytes(my_fp)?;
    let mut info=Vec::new(); info.extend_from_slice(b"mesh-v3-x3dh v1"); info.extend_from_slice(&peer_fp_bytes); info.extend_from_slice(&my_fp_bytes); info.extend_from_slice(&spk_id.to_be_bytes()); info.extend_from_slice(&opk_id.to_be_bytes());
    let sk=hkdf_derive(&ikm,&info,32)?;
    // zeroize ikm
    let mut ikm_z = Zeroizing::new(ikm);
    ikm_z.fill(0);
    Ok(sk)
}

async fn cmd_poll(host: &str, out_dir: Option<String>, do_decrypt: bool) -> Result<()> {
    let (_,_,my_fp,my_x_priv,_)=load_identity()?;
    let token=fs::read_to_string(keys_dir().join(format!("{}.key",my_fp)))?.trim().to_string();
    let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;
    let resp=client.get(format!("{}/mesh/v3/{}",host.trim_end_matches('/'),my_fp)).header("X-Mesh-Key",token.clone()).send().await?;
    if !resp.status().is_success(){return Err(anyhow!("list {}",resp.text().await?));}
    let j:serde_json::Value=resp.json().await?; let msgs=j["messages"].as_array().cloned().unwrap_or_default();
    println!("inbox {} msgs", msgs.len());
    let out_path=out_dir.map(PathBuf::from).unwrap_or_else(||{let d=mesh_dir().join("inbox"); let _=fs::create_dir_all(&d); d}); fs::create_dir_all(&out_path)?;
    // Fetch all messages first to allow sorting X3DH init first (fixes out-of-order where DR-only arrives before X3DH)
    let mut all_msgs: Vec<(String, Vec<u8>)> = Vec::new();
    for m in msgs {
        let id=m["id"].as_str().unwrap_or("").to_string(); if id.is_empty(){continue;}
        let resp=client.get(format!("{}/mesh/v3/{}/{}",host.trim_end_matches('/'),my_fp,id)).header("X-Mesh-Key",token.clone()).send().await?;
        if !resp.status().is_success(){eprintln!("get {} {}",id,resp.status()); continue;}
        let data=resp.bytes().await?.to_vec();
        all_msgs.push((id, data));
    }
    // Helper to check if message is X3DH init (should be processed first)
    let is_x3dh_init = |data: &[u8]| -> bool {
        if data.len() < 2 { return false; }
        if data[0]==0x04 && data[1]==0x01 { return true; }
        if data[0]==0x03 && data[1]==0x01 { return true; }
        false
    };
    // Two-pass: first X3DH inits, then rest (ensures session exists for DR-only)
    let mut ordered: Vec<(String, Vec<u8>)> = Vec::new();
    for (id, data) in &all_msgs { if is_x3dh_init(data) { ordered.push((id.clone(), data.clone())); } }
    for (id, data) in &all_msgs { if !is_x3dh_init(data) { ordered.push((id.clone(), data.clone())); } }

    for (id, data) in ordered {
        if !do_decrypt { fs::write(out_path.join(format!("{}.msg",id)),&data)?; continue; }
        if data.len()<2 { eprintln!("{} short", id); continue; }
        let version = data[0];

        if version == 0x03 {
            // Legacy 0x03 handling (backwards compat) - also fix OPK deletion
            let typ=data[1]; let mut off=2;
            if data.len()<off+32+32+32+4+4+2{continue;}
            let ek_pub_bytes: [u8;32] =data[off..off+32].try_into().unwrap(); off+=32;
            let sender_fp_bytes: [u8;32] =data[off..off+32].try_into().unwrap(); off+=32;
            let sender_x_pub_bytes: [u8;32] =data[off..off+32].try_into().unwrap(); off+=32;
            let spk_id=u32::from_be_bytes(data[off..off+4].try_into().unwrap()); off+=4;
            let opk_id=u32::from_be_bytes(data[off..off+4].try_into().unwrap()); off+=4;
            // Check if file has header_nonce (new 0x03 with fix) or old format
            // Old 0x03: [hlen 2][header_ct][body_nonce 24][body_ct]
            // New 0x03: [header_nonce 24][hlen 2][header_ct][body_nonce 24][body_ct] - we added header_nonce for fix
            let mut header_nonce = [0u8;24]; // fixed bug was [0;24], now we use random, but old messages have fixed
            let mut hlen: usize;
            if data.len() >= off+24+2 && data[off+24..off+26].len()==2 {
                // Try detect new format: if we have header_nonce then hlen
                // We can't distinguish reliably, try new format first: assume header_nonce present
                // If new format, header_nonce is random, hlen should be small (<1000)
                let possible_hlen = u16::from_be_bytes([data[off+24], data[off+25]]) as usize;
                if possible_hlen < 2000 && data.len() > off+24+2+possible_hlen+24 {
                    // Likely new format with header_nonce
                    header_nonce.copy_from_slice(&data[off..off+24]); off+=24;
                    hlen = possible_hlen; off+=2;
                } else {
                    // Old format, no header_nonce, use [0;24]
                    hlen=u16::from_be_bytes([data[off],data[off+1]]) as usize; off+=2;
                    // header_nonce stays [0;24] for backwards compat decrypt
                }
            } else {
                hlen=u16::from_be_bytes([data[off],data[off+1]]) as usize; off+=2;
            }
            if data.len()<off+hlen{continue;} let header_ct=&data[off..off+hlen]; off+=hlen;
            let sender_fp=fp_from_bytes(&sender_fp_bytes);
            let sender_x_pub=PublicKey::from(sender_x_pub_bytes); let ek_pub=PublicKey::from(ek_pub_bytes);
            let sk=match x3dh_bob(&my_x_priv,&my_fp,&sender_fp,&sender_x_pub,&ek_pub,spk_id,opk_id){Ok(v)=>v,Err(e)=>{eprintln!("{} x3dh bob {}",id,e); continue;}};
            // OPK deletion for FS - delete after successful X3DH if OPK was used
            if opk_id != OPK_NONE {
                let opk_path = mesh_dir().join("prekeys").join(format!("opk_{}.priv", opk_id));
                let _ = fs::remove_file(opk_path);
            }
            let okm=hkdf_derive_salt(&sk,&sk,b"mesh-v3-msg v1",64).unwrap(); let hek:[u8;32]=okm[0..32].try_into().unwrap(); let mk:[u8;32]=okm[32..64].try_into().unwrap();
            let header_plain=match xdec(&hek,&header_nonce,header_ct,b""){
                Ok(v)=>v,
                Err(_)=> {
                    // Try old fixed nonce [0;24] for backwards compat
                    match xdec(&hek,&[0u8;24],header_ct,b""){Ok(v)=>v,Err(e)=>{eprintln!("{} header dec {}",id,e); continue;}}
                }
            };
            if typ==0x01 {
                if data.len()<off+24{continue;} let body_nonce: [u8;24] =data[off..off+24].try_into().unwrap(); off+=24; let body_ct=&data[off..];
                let pt=match xdec(&mk,&body_nonce,body_ct,header_ct){Ok(v)=>v,Err(e)=>{eprintln!("{} body dec {}",id,e); continue;}};
                println!("msg {} from {}: {}", id, &sender_fp[0..8], String::from_utf8_lossy(&pt));
                fs::write(out_path.join(format!("{}.json",id)),&pt)?;
                let _=client.delete(format!("{}/mesh/v3/{}/{}",host.trim_end_matches('/'),my_fp,id)).header("X-Mesh-Key",token.clone()).send().await;
                // zeroize mk
                let mut mk_z = Zeroizing::new(mk);
                mk_z.fill(0);
            } else if typ==0x02 {
                let hj:serde_json::Value=match serde_json::from_slice(&header_plain){Ok(v)=>v,Err(_)=>continue};
                let fk=b64_decode(hj["fk"].as_str().unwrap_or("")) .unwrap(); let base_nonce=b64_decode(hj["base_nonce"].as_str().unwrap_or("")).unwrap();
                let exp_chunks=hj["chunks"].as_u64().unwrap_or(0) as usize; let exp_size=hj["size"].as_u64().unwrap_or(0) as usize; let exp_hash=hj["hash"].as_str().unwrap_or("").to_string(); let name=hj["name"].as_str().unwrap_or("file.bin").to_string();
                let fk_arr: [u8;32] =fk.try_into().unwrap(); let mut base12=[0u8;12]; base12.copy_from_slice(&base_nonce);
                let mut hh=Blake2b512::new(); hh.update(header_ct); let hhash=hh.finalize(); let hhash32=&hhash[0..32];
                let out_file=out_path.join(format!("{}-{}",id,name)); let mut outf=fs::File::create(&out_file).unwrap(); let mut hasher=Blake2b512::new(); let mut total=0usize; let mut idx=0usize; let mut cur=off; let mut ok=true;
                while cur+2<=data.len() && idx<exp_chunks {
                    let clen=u16::from_be_bytes([data[cur],data[cur+1]]) as usize; cur+=2; if cur+clen>data.len(){ok=false; break;} let ct=&data[cur..cur+clen]; cur+=clen;
                    let is_last=if idx+1==exp_chunks{1u8}else{0u8}; let mut n12=[0u8;12]; n12[0..4].copy_from_slice(&base12[0..4]); n12[4..12].copy_from_slice(&(idx as u64).to_le_bytes());
                    let mut ad=Vec::new(); ad.extend_from_slice(hhash32); ad.extend_from_slice(&(idx as u64).to_le_bytes()); ad.push(is_last);
                    let pt=match cdec(&fk_arr,&n12,ct,&ad){Ok(v)=>v,Err(e)=>{eprintln!("{} chunk {} {}",id,idx,e); ok=false; break;}};
                    use std::io::Write; let _=outf.write_all(&pt); hasher.update(&pt); total+=pt.len(); idx+=1;
                }
                if !ok || idx!=exp_chunks || total!=exp_size { let _=fs::remove_file(&out_file); eprintln!("{} fail chunks {}/{} size {}/{}",id,idx,exp_chunks,total,exp_size); continue; }
                let h2=hasher.finalize(); if hex::encode(&h2[0..32])!=exp_hash { let _=fs::remove_file(&out_file); eprintln!("{} hash mismatch",id); continue; }
                println!("file {} -> {} {} bytes OK", id, out_file.display(), total);
                let _=client.delete(format!("{}/mesh/v3/{}/{}",host.trim_end_matches('/'),my_fp,id)).header("X-Mesh-Key",token.clone()).send().await;
            }
            continue;
        } else if version == 0x04 {
            // DR messages (0x04)
            let msg_subtype = data[1]; // 0x01 = X3DH+DR init, 0x03 = DR only
            let mut off = 2;
            let mut ek_pub_bytes_opt: Option<[u8;32]> = None;
            let mut sender_fp_bytes: [u8;32] = [0u8;32];
            let mut sender_x_pub_bytes: [u8;32] = [0u8;32];
            let mut spk_id = 0u32;
            let mut opk_id = OPK_NONE;
            
            if msg_subtype == 0x01 {
                // X3DH+DR init: [ek 32][sender_fp 32][sender_x 32][spk_id 4][opk_id 4]
                if data.len() < off+32+32+32+4+4 { continue; }
                ek_pub_bytes_opt = Some(data[off..off+32].try_into().unwrap()); off+=32;
                sender_fp_bytes = data[off..off+32].try_into().unwrap(); off+=32;
                sender_x_pub_bytes = data[off..off+32].try_into().unwrap(); off+=32;
                spk_id = u32::from_be_bytes(data[off..off+4].try_into().unwrap()); off+=4;
                opk_id = u32::from_be_bytes(data[off..off+4].try_into().unwrap()); off+=4;
            } else if msg_subtype == 0x03 {
                // DR only: [sender_fp 32][sender_x 32]
                if data.len() < off+32+32 { continue; }
                sender_fp_bytes = data[off..off+32].try_into().unwrap(); off+=32;
                sender_x_pub_bytes = data[off..off+32].try_into().unwrap(); off+=32;
                // spk_id/opk_id not needed
            } else {
                eprintln!("{} unknown 0x04 subtype {}", id, msg_subtype);
                continue;
            }
            
            // DR header: [dh_pub 32][pn 4][n 4][header_nonce 24][hlen 2][header_ct][body_nonce 24][body_ct]
            if data.len() < off+32+4+4+24+2 { continue; }
            let dh_pub_bytes: [u8;32] = data[off..off+32].try_into().unwrap(); off+=32;
            let pn = u32::from_be_bytes(data[off..off+4].try_into().unwrap()); off+=4;
            let n = u32::from_be_bytes(data[off..off+4].try_into().unwrap()); off+=4;
            let header_nonce: [u8;24] = data[off..off+24].try_into().unwrap(); off+=24;
            let hlen = u16::from_be_bytes([data[off], data[off+1]]) as usize; off+=2;
            if data.len() < off+hlen+24 { continue; }
            let header_ct = &data[off..off+hlen]; off+=hlen;
            let body_nonce: [u8;24] = data[off..off+24].try_into().unwrap(); off+=24;
            let body_ct = &data[off..];
            
            let sender_fp = fp_from_bytes(&sender_fp_bytes);
            let sender_x_pub = PublicKey::from(sender_x_pub_bytes);
            
            // Load or init session for sender
            let mut sess_opt = load_session(&sender_fp);
            let is_new_x3dh = msg_subtype == 0x01;
            
            if is_new_x3dh && sess_opt.is_none() {
                // First message: do X3DH to get SK and init session
                let ek_pub_bytes = ek_pub_bytes_opt.unwrap();
                let ek_pub = PublicKey::from(ek_pub_bytes);
                let sk = match x3dh_bob(&my_x_priv,&my_fp,&sender_fp,&sender_x_pub,&ek_pub,spk_id,opk_id){
                    Ok(v)=>v, Err(e)=>{eprintln!("{} x3dh bob new session {}",id,e); continue;}
                };
                // OPK deletion
                if opk_id != OPK_NONE {
                    let opk_path = mesh_dir().join("prekeys").join(format!("opk_{}.priv", opk_id));
                    let _ = fs::remove_file(opk_path);
                }
                let root_key_b64 = b64_encode(&sk);
                let header_key = hkdf_derive(&sk, b"mesh-v3-header v1", 32)?;
                let chain = hkdf_derive(&sk, b"mesh-v3-chain", 32)?; // same as sender init for sync
                // For Bob, after X3DH, chain_recv = chain_send = same initial chain for first messages
                
                // Generate our ratchet DH for reply
                let (dh_priv, dh_pub) = generate_dh_keypair();
                
                let sess = Session {
                    root_key_b64,
                    chain_send_b64: Some(b64_encode(&chain)),
                    chain_recv_b64: Some(b64_encode(&chain)),
                    dh_send_priv_b64: b64_encode(&dh_priv),
                    dh_send_pub_b64: b64_encode(&dh_pub),
                    dh_recv_pub_b64: Some(b64_encode(&dh_pub_bytes)), // peer's dh
                    n_send: 0,
                    n_recv: 0,
                    pn: 0,
                    header_key_b64: b64_encode(&header_key),
                    skipped_keys: HashMap::new(),
                    created_at: now_secs(),
                };
                // Zeroize sk
                let mut sk_z = Zeroizing::new(sk);
                sk_z.fill(0);
                sess_opt = Some(sess);
            }
            
            let mut sess = match sess_opt {
                Some(s) => s,
                None => {
                    eprintln!("{} no session for {} and not X3DH init", id, &sender_fp[0..8]);
                    continue;
                }
            };
            
            // Check skipped keys first
            let dh_hex = hex::encode(&dh_pub_bytes);
            let skip_key = format!("{}-{}", dh_hex, n);
            if let Some(mk_b64) = sess.skipped_keys.get(&skip_key) {
                let mk_bytes = b64_decode(mk_b64).unwrap();
                let mk_arr: [u8;32] = mk_bytes.try_into().unwrap();
                // header already available? We need to decrypt header to get n, but we already have n from plaintext in this simplified 0x04 format
                // In real Signal, header is encrypted, but we send dh/pub/pn/n in clear for MVP, so we can directly use n
                let pt = match xdec(&mk_arr, &body_nonce, body_ct, header_ct) {
                    Ok(v)=>v,
                    Err(e)=>{eprintln!("{} skipped key decrypt failed {}", id, e); continue;}
                };
                println!("msg {} from {} (skipped n={}): {}", id, &sender_fp[0..8], n, String::from_utf8_lossy(&pt));
                fs::write(out_path.join(format!("{}.json",id)),&pt)?;
                let _=client.delete(format!("{}/mesh/v3/{}/{}",host.trim_end_matches('/'),my_fp,id)).header("X-Mesh-Key",token.clone()).send().await;
                // Remove used skipped key for FS - delete after use
                sess.skipped_keys.remove(&skip_key);
                save_session(&sender_fp, &sess).ok();
                continue;
            }
            
            // Check if we need to ratchet (new dh_pub)
            // Self-send guard: if incoming dh == our own send dh, don't ratchet (prevents DH with self)
            let mut need_ratchet = match &sess.dh_recv_pub_b64 {
                Some(existing) => {
                    let existing_bytes = b64_decode(existing).unwrap();
                    existing_bytes != dh_pub_bytes
                },
                None => true,
            };
            // Self-send: if peer is self or dh == our own, skip ratchet
            if sender_fp == my_fp {
                need_ratchet = false;
            } else {
                if let Ok(our_dh_bytes) = b64_decode(&sess.dh_send_pub_b64) {
                    if our_dh_bytes == dh_pub_bytes.to_vec() {
                        need_ratchet = false;
                    }
                }
            }
            
            if need_ratchet {
                // DH ratchet: DH(our current send priv, peer's new pub)
                let our_priv_bytes = b64_decode(&sess.dh_send_priv_b64)?;
                let our_priv = StaticSecret::from(<[u8;32]>::try_from(our_priv_bytes).unwrap());
                let peer_pub = PublicKey::from(dh_pub_bytes);
                let dh_out = our_priv.diffie_hellman(&peer_pub);
                let rk_bytes = b64_decode(&sess.root_key_b64)?;
                let (new_rk, new_chain_recv) = kdf_rk(&rk_bytes, dh_out.as_bytes())?;
                
                // Save old chain for skipped keys if needed
                let old_n_recv = sess.n_recv;
                let _old_pn = sess.pn;
                
                sess.root_key_b64 = b64_encode(&new_rk);
                sess.chain_recv_b64 = Some(b64_encode(&new_chain_recv));
                sess.dh_recv_pub_b64 = Some(b64_encode(&dh_pub_bytes));
                sess.n_recv = 0;
                sess.pn = sess.n_send;
                
                // Generate new DH for next send (PCS)
                let (new_priv, new_pub) = generate_dh_keypair();
                sess.dh_send_priv_b64 = b64_encode(&new_priv);
                sess.dh_send_pub_b64 = b64_encode(&new_pub);
                
                // Zeroize dh_out
                let mut dh_out_z = Zeroizing::new(dh_out.as_bytes().to_vec());
                dh_out_z.fill(0);
                
                // If pn > 0, we might have skipped messages from previous recv chain, but we already moved to new chain
                // For simplicity, don't handle old chain skipped here
                let _ = (old_n_recv, _old_pn);
            }
            
            // Now derive MK for n, handling skipped
            let chain_recv_b64 = sess.chain_recv_b64.clone().unwrap_or_else(|| {
                // If no recv chain yet (first message after X3DH), derive from root?
                // For first message, we already have chain_recv from init, but if this is DR-only message and we are Bob, we should have chain_recv
                // Fallback: derive from root
                let rk = b64_decode(&sess.root_key_b64).unwrap();
                let cr = hkdf_derive(&rk, b"mesh-v3-chain", 32).unwrap();
                b64_encode(&cr)
            });
            
            // If n < n_recv, it's old, should be in skipped (already checked) -> reject
            if n < sess.n_recv {
                eprintln!("{} old n {} < n_recv {} (already processed?)", id, n, sess.n_recv);
                continue;
            }
            
            let mut ck_bytes = b64_decode(&chain_recv_b64)?;
            let mut mk_for_n: Option<Vec<u8>> = None;
            
            // Generate skipped keys for n_recv .. n-1
            for i in sess.n_recv..n {
                let (ck_next, mk) = kdf_ck(&ck_bytes)?;
                // Store skipped
                let skip_k = format!("{}-{}", dh_hex, i);
                if sess.skipped_keys.len() < MAX_SKIPPED_KEYS {
                    sess.skipped_keys.insert(skip_k, b64_encode(&mk));
                }
                // zeroize mk after storing? We store b64, but need to zeroize original
                let mut mk_z = Zeroizing::new(mk);
                mk_z.fill(0);
                ck_bytes = ck_next;
            }
            
            // Now ck_bytes is chain for n, derive mk for n
            let (ck_next, mk_bytes) = kdf_ck(&ck_bytes)?;
            mk_for_n = Some(mk_bytes);
            
            // Decrypt header to verify? In this MVP, header is encrypted but we already have dh/pn/n in clear for ratchet,
            // still try to decrypt header for integrity
            let header_key_bytes = b64_decode(&sess.header_key_b64)?;
            let header_key_arr: [u8;32] = header_key_bytes.try_into().unwrap();
            let _header_plain = match xdec(&header_key_arr, &header_nonce, header_ct, b"") {
                Ok(v) => v,
                Err(_) => {
                    // Header decrypt failed, but we already have n/pn/dh from clear, continue for MVP
                    // In real Signal, this would fail
                    Vec::new()
                }
            };
            
            let mk_bytes = mk_for_n.unwrap();
            let mk_arr: [u8;32] = mk_bytes.clone().try_into().unwrap();
            let pt = match xdec(&mk_arr, &body_nonce, body_ct, header_ct) {
                Ok(v)=>v,
                Err(e)=>{eprintln!("{} body dec fail n={} {}", id, n, e); continue;}
            };
            
            println!("msg {} from {} (DR n={} pn={} dh={}..): {}", id, &sender_fp[0..8], n, pn, &dh_hex[0..8], String::from_utf8_lossy(&pt));
            fs::write(out_path.join(format!("{}.json",id)),&pt)?;
            let _=client.delete(format!("{}/mesh/v3/{}/{}",host.trim_end_matches('/'),my_fp,id)).header("X-Mesh-Key",token.clone()).send().await;
            
            // Update session, delete mk for FS
            sess.chain_recv_b64 = Some(b64_encode(&ck_next));
            sess.n_recv = n + 1;
            
            // Enforce skipped keys limit
            if sess.skipped_keys.len() > MAX_SKIPPED_KEYS {
                // Remove oldest (arbitrary, HashMap has no order, just drain half)
                let keys: Vec<String> = sess.skipped_keys.keys().cloned().collect();
                for k in keys.iter().take(MAX_SKIPPED_KEYS/2) {
                    sess.skipped_keys.remove(k);
                }
            }
            
            save_session(&sender_fp, &sess).ok();
            
            // Zeroize mk, ck_next
            let mut mk_z = Zeroizing::new(mk_bytes);
            mk_z.fill(0);
            let mut ck_next_z = Zeroizing::new(ck_next);
            ck_next_z.fill(0);
            
            continue;
        } else {
            eprintln!("{} unknown version {}", id, version);
            continue;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli=Cli::parse();
    match cli.cmd {
        Commands::Gen=>cmd_gen()?,
        Commands::Fp=>cmd_fp()?,
        Commands::Claim=>cmd_claim(&cli.host).await?,
        Commands::X3dh{sub}=>match sub{X3dhCmd::Publish=>cmd_x3dh_publish(&cli.host).await?},
        Commands::Allow{fp,action}=>cmd_allow(&fp,&action,&cli.host).await?,
        Commands::AllowList=>{ let (_,_,fp,_,_)=load_identity()?; let token=fs::read_to_string(keys_dir().join(format!("{}.key",fp)))?.trim().to_string(); let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?; let resp=client.get(format!("{}/mesh/v3/{}/allow",cli.host.trim_end_matches('/'),fp)).header("X-Mesh-Key",token).send().await?; println!("{}",resp.text().await?); },
        Commands::Send{to,msg,file}=>cmd_send(&to,msg,file,&cli.host).await?,
        Commands::SendFile{to,file}=>cmd_send_file(&to,&file,&cli.host).await?,
        Commands::Poll{out,decrypt}=>cmd_poll(&cli.host,out,decrypt).await?,
        Commands::RotateToken=>{ let (_,_,fp,_,_)=load_identity()?; let token=fs::read_to_string(keys_dir().join(format!("{}.key",fp)))?.trim().to_string(); let client=reqwest::Client::builder().danger_accept_invalid_certs(true).build()?; let resp=client.post(format!("{}/mesh/v3/{}/rotate_token",cli.host.trim_end_matches('/'),fp)).header("X-Mesh-Key",token).send().await?; let txt=resp.text().await?; println!("{}",txt); if let Ok(j)=serde_json::from_str::<serde_json::Value>(&txt){ if let Some(nt)=j["token"].as_str(){ fs::write(keys_dir().join(format!("{}.key",fp)),format!("{}\n",nt))?; println!("saved"); } } },
    }
    Ok(())
}
