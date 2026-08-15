# การแปลผล scan.json → หมายเลขข้อในเช็คลิสต์

`build_report.py` ทำการ map นี้อัตโนมัติแล้ว เอกสารนี้ไว้ใช้เมื่อ **ต้องตีความเอง** หรืออธิบายให้ผู้ใช้ฟังว่าเลขข้อไหนมาจากไหน

## ตารางการ map

| ฟิลด์ใน JSON | ข้อที่ | เกณฑ์ผ่าน |
|---|---|---|
| `tls.protocols` | 1 | ไม่มี `tls1` และ `tls1_1` — แต่ถ้าอยู่ใน `tls.protocols_unknown` แปลว่า openssl บนเครื่องต่อไม่ได้ ให้ผลเป็น **ยังไม่ตรวจ** ห้ามนับว่าผ่าน |
| `tls.days_left` | 3 | มากกว่า 30 |
| `tls.key_bits` | 6 | ≥ 2048 |
| `tls.ocsp_stapling` | 11 | true (ถ้า `tls.handshake_ok` เป็น false → ยังไม่ตรวจ) |
| `headers.strict-transport-security` | 7, 8 | max-age ≥ 31536000 / มี includeSubDomains |
| `headers.content-security-policy` | 15, 16 | มี CSP ที่ไม่ใช้ unsafe-inline/eval / มี frame-ancestors |
| `headers.x-frame-options` | 17 | DENY หรือ SAMEORIGIN |
| `headers.x-content-type-options` | 18 | nosniff |
| `headers.referrer-policy` | 19 | มีค่า |
| `headers.permissions-policy` | 20 | มีค่า |
| `headers.server` / `x-powered-by` | 21 | ไม่มีตัวเลขเวอร์ชัน |
| `headers.access-control-allow-*` | 22 | ไม่ใช่ `*` คู่กับ credentials: true |
| `headers.content-type` | 27 | มี charset |
| `http_redirect` | 9 | status 301/308 ไปยัง https:// |
| `page.mixed_content_refs` | 10 | เท่ากับ 0 |
| `cookies[].httponly / secure / samesite` | 67, 68, 69 | ทุก cookie ต้องมีครบ |
| `directory_listing_hint` | 29 | false |
| `exposed_paths` `/.git/*`, `/.svn/*` | 30 | ไม่มีตัวไหนคืน 200 |
| `exposed_paths` `.env`, `.bak`, `.DS_Store` | 31 | ไม่มีตัวไหนคืน 200 |
| `exposed_paths` `phpinfo/info/test.php` | 32 | ไม่มีตัวไหนคืน 200 |
| `exposed_paths` `/backup/ /old/ /temp/ …` | 35 | ไม่มีตัวไหนคืน 200 |
| `exposed_paths` `*.sql`, `backup.zip` | 36 | ไม่มีตัวไหนคืน 200 |
| `page.possible_secret_matches` | 38 | เท่ากับ 0 |
| `exposed_paths./robots.txt` | 40 | คืน 200 |
| `exposed_paths` `package.json` ฯลฯ | 41 | ไม่มีตัวไหนคืน 200 |
| `exposed_paths` `/phpmyadmin/`, `/adminer.php` | 128 | ไม่คืน 200 |
| `exposed_paths./.well-known/security.txt` | 147 | คืน 200 |
| `dns.spf` + `dns.dmarc` | 136 | มีทั้งคู่ |
| `page.scripts_with_sri` | 122 | มี SRI ถ้ามี script ภายนอก |
| `page.external_script_domains` | 173 | ใช้เป็น inventory ให้ผู้ใช้ทบทวน |
| `page.trackers_on_load` | 163 | ถ้ามี tracker โหลดทันที = ต้องยืนยันเรื่อง consent |
| `project.npm_vulnerabilities` | 114 | critical + high = 0 |
| `project.lockfile_committed` | 123 | true |
| `project.world_writable_files` | 133 | เท่ากับ 0 |
| `project.files_with_possible_secrets` | 113 | เท่ากับ 0 |

## หลักการตีความ

**ไม่มีข้อมูล ≠ ผ่าน** ถ้าฟิลด์เป็น `null`, `skipped: true` หรือสคริปต์รันไม่สำเร็จ ให้สถานะ "ยังไม่ตรวจ" เสมอ การรายงานว่า "ผ่าน" ทั้งที่ไม่ได้ตรวจ อันตรายกว่าการไม่รายงาน เพราะทำให้เจ้าของเว็บเลิกสนใจจุดนั้น

**ผลบวกลวงที่พบบ่อย** — อธิบายให้ผู้ใช้ทราบเมื่อเจอ:
- `possible_secret_matches` มักจับคำว่า `apiKey` ที่เป็นชื่อตัวแปรเปล่า ๆ หรือ public key ของ Stripe/Google Maps ซึ่งเปิดเผยได้ตามปกติ → ต้องเปิดดูจริงก่อนสรุป
- `Server: nginx` เฉย ๆ ไม่มีเวอร์ชัน = ไม่ถือว่าไม่ผ่านข้อ 21
- เว็บที่อยู่หลัง Cloudflare อาจไม่คืน header จริงของ origin — ผลบางข้อสะท้อน Cloudflare ไม่ใช่ server ของผู้ใช้ ให้ระบุไว้ในรายงาน
- SPA ที่ render ด้วย JS ทำให้ `mixed_content_refs` และ `external_script_domains` ต่ำกว่าความจริง เพราะสคริปต์อ่านเฉพาะ HTML ตอนแรก
- `/robots.txt` คืน 200 ที่จริงเป็นแค่ "มีไฟล์" ยังต้องเปิดดูว่าเผย admin path หรือเปล่า (ข้อ 40 ตรวจได้แค่ครึ่งเดียว)

**ข้อที่ต้องดูคู่กันเสมอ** — ถ้า `/.git/config` เข้าถึงได้ (ข้อ 30) ให้ถือว่าข้อ 113 (secret ใน git history) เสี่ยงสูงทันที เพราะคนอื่นโคลน repo ทั้งก้อนได้

## เมื่อผลตัดสินไม่ได้

| สัญญาณใน JSON | ผลกับข้อไหน | ต้องรายงานว่า |
|---|---|---|
| `tls.skipped: true` | 1, 3, 6, 11 | ยังไม่ตรวจ — เครื่องที่รันสแกนไม่มี openssl |
| `tls.protocols_unknown` มี `tls1`/`tls1_1` | 1 | ยังไม่ตรวจ — openssl รุ่นใหม่ไม่ยอม *เสนอ* โปรโตคอลเก่า จึงไม่เคยถามเซิร์ฟเวอร์จริง ให้ยืนยันด้วย SSL Labs หรือ `nmap --script ssl-enum-ciphers` |
| `path_baseline.soft_404: true` | 30–41, 128, 147 | ยังไม่ตรวจ — เว็บตอบ 200 ให้ path ที่ไม่มีจริง status code จึงตัดสินไม่ได้ ต้องเปิดดูเนื้อหาไฟล์เอง |

กฎเดียวที่ห้ามผ่อน: **ไม่มีหลักฐาน ≠ ผ่าน**
