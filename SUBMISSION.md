# Wildcard Submission — Draft (isi form, belum dikirim)

Event: zkVerify Agent Games — Wildcard track (Event 03).
Tutup submisi: 21 Nov 2026. Penjurian 22–30 Nov, pemenang 1 Des 2026.

## AGENT LINK

`https://github.com/jackspierrow/hextor-audit-agent`
(PLACEHOLDER — repo publik belum dibuat; deploy/pembuatan repo urusan
parent. Kode lengkap sudah ada di `~/workspace/zkverify-agent-games/agent/`.)

## PUBLIC ENDPOINT

`https://hextor-audit-agent.vercel.app`
(PLACEHOLDER — belum di-deploy; deploy urusan parent. Struktur Vercel
Python serverless sudah siap di `api/index.py` + `vercel.json`.)

- `GET /health` → `{"status": "ok"}`
- `POST /audit {"domain": "example.com"}` → audit JSON
- Auth: header `X-Signature` = HMAC-SHA256 hex dari body mentah, kunci
  dari env `AGENT_SHARED_SECRET`. Kalau secret tidak di-set, endpoint
  jalan terbuka (demo).

## USE CASE

Security researchers dan pemilik situs butuh cara cepat dan jujur untuk
memeriksa apakah `security.txt` sebuah domain masih bisa dipakai:
apakah filenya ada, apakah `Contact`-nya masih hidup, apakah
`Encryption`-nya menunjuk ke kunci yang benar-benar bisa diambil,
apakah `Expires`-nya sudah lewat.

Hari ini pengecekan itu manual — buka file, klik tiap link satu-satu.
Hextor Audit Agent mengotomatiskannya dalam satu panggilan API, dengan
aturan bukti yang sama seperti perburuan bug bounty sungguhan:
setiap klaim "URL mati" harus lolos **dua kali fetch live**,
blokir WAF bukan temuan, dan severity tidak pernah melebihi dampak
yang terbukti. Yang terbantu: peneliti sebelum mengirim laporan
(supaya laporannya tidak nyangkut di link mati) dan tim kecil yang
mau memastikan kanal lapor kerentanan mereka masih berfungsi.

## BUILD CONTEXT

- Python 3.10+, **stdlib saja** (urllib, http.server, hmac, hashlib) —
  tanpa dependency, tanpa layanan berbayar, supaya deploy ke Vercel
  tinggal `vercel deploy`.
- `api/index.py`: satu file. `validate_domain()` menolak localhost /
  IP privat / hostname tidak valid (SSRF guard). `http_fetch()` ambil
  `/.well-known/security.txt` (ikut redirect, timeout 10 detik,
  User-Agent jelas). `parse_security_txt()` parse field RFC 9116.
  `check_url_live_twice()` verifikasi tiap URL kontak/enkripsi/policy
  dua kali (HEAD, fallback GET); hanya dua kali gagal yang disebut
  mati. `audit_domain()` hitung skor (100 − 10 low / 20 medium /
  30 high) dan verdict pass / needs-attention / fail.
- `vercel.json`: route semua request ke `api/index.py`.
- Agent ini **read-only**: tidak pernah mengirim laporan/email, tidak
  login ke situs apa pun, tidak menyentuh kredensial atau wallet.
- Metodologi diadaptasi dari checklist verifikasi perburuan bug bounty
  kami (87 laporan terverifikasi terkirim): bukti live 2×, validasi
  adversarial, severity jujur. Tidak ada laporan/draft bounty yang
  di-copy ke agent ini.

## ZKVERIFY (OPTIONAL)

Setiap temuan agent ini adalah **klaim yang bisa dicek ulang siapa
pun dalam 10 detik** dengan `curl` ke `/.well-known/security.txt`
domain yang sama — buktinya adalah isi file publik dan status HTTP
langsung, bukan pernyataan agent semata.

**Proof zkVerify tidak dipakai di v1.** Aturan Wildcard menyebut
penulisan proof zkVerify itu opsional, jadi kami menulis jujur:
belum ada integrasi `POST /v1/submitProof` di versi ini. Rencana
berikutnya (di luar submisi ini): bungkus hasil audit sebagai klaim
terstruktur (domain + hash isi security.txt + timestamp) dan
verifikasi klaim itu lewat zkVerify, supaya "file ini berisi X pada
waktu T" menjadi klaim yang bisa dibuktikan tanpa percaya pada
server agent.
