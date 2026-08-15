# วิธีแก้ที่ก๊อปไปใช้ได้ (nginx / Apache / PHP / Laravel / Cloudflare)

อ่านไฟล์นี้เมื่อผู้ใช้ถามว่า "แล้วแก้ยังไง" หรือเมื่อเขียนคอลัมน์วิธีแก้ในรายงาน
เตือนผู้ใช้เสมอว่าให้ทดสอบบน staging ก่อน แล้ว `nginx -t` / `apachectl configtest` ก่อน reload

## Security headers (ข้อ 7, 8, 15–20, 27)

**nginx** — ใส่ใน `server {}` block
```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; upgrade-insecure-requests" always;
server_tokens off;
```

**Apache** — ใน `.htaccess` หรือ vhost (ต้องเปิด `mod_headers`)
```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always unset X-Powered-By
ServerTokens Prod
ServerSignature Off
```

**CSP อย่างปลอดภัย** — อย่าให้ผู้ใช้เปิด CSP แบบเข้มทันทีบน production เว็บจะพัง ให้เริ่มด้วย report-only ก่อน:
```nginx
add_header Content-Security-Policy-Report-Only "default-src 'self'; report-uri /csp-report" always;
```
รันสัก 1–2 สัปดาห์ เก็บ report ดูว่าอะไรพัง แล้วค่อยเปลี่ยนเป็น enforce

## บล็อกไฟล์ที่ไม่ควรเข้าถึง (ข้อ 30, 31, 32, 35, 36, 41)

**nginx**
```nginx
location ~ /\.(git|svn|env|ht|DS_Store) { deny all; return 404; }
location ~* \.(sql|bak|old|log|zip|tar\.gz)$ { deny all; return 404; }
location ~* ^/(backup|backups|old|temp|tmp|dev|test)/ { deny all; return 404; }
location ~* ^/(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock)$ { deny all; return 404; }
autoindex off;
```

**Apache**
```apache
RedirectMatch 404 /\.(git|svn|env|DS_Store)
<FilesMatch "\.(sql|bak|old|log|zip)$">
  Require all denied
</FilesMatch>
Options -Indexes
```

**ต้นเหตุที่แท้จริง** — ถ้า `.git` หรือ `.env` เข้าถึงได้ แปลว่า deploy ด้วยการ `git pull` ลง web root หรือชี้ document root ผิดที่ ควรแก้ที่ deployment flow ด้วย ไม่ใช่แค่บล็อก URL และถ้า `.env` เคยหลุด **ต้องหมุน credential ทุกตัวในไฟล์นั้นทันที** เพราะอาจถูกอ่านไปแล้ว

## HTTP → HTTPS + TLS (ข้อ 1, 9)

```nginx
server {
    listen 80;
    server_name example.com www.example.com;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_stapling on;
    ssl_stapling_verify on;
}
```

## Cookie flags (ข้อ 67, 68, 69)

**PHP** — `php.ini`
```ini
session.cookie_httponly = 1
session.cookie_secure = 1
session.cookie_samesite = "Lax"
session.use_strict_mode = 1
```

**Laravel** — `config/session.php`: `'secure' => true, 'http_only' => true, 'same_site' => 'lax'`

**Express** — `app.use(session({ cookie: { httpOnly: true, secure: true, sameSite: 'lax' } }))`

## Secret ที่หลุดใน frontend หรือ git (ข้อ 38, 113)

ลำดับที่ถูกต้องคือ **หมุน key ก่อน แล้วค่อยลบ** — การลบไฟล์ออกจาก repo ไม่ได้ทำให้ key ที่หลุดไปแล้วปลอดภัยขึ้น
1. สร้าง key ใหม่ในระบบต้นทาง (Google Cloud, TikTok, Shopee, Stripe ฯลฯ) แล้วเพิกถอนตัวเก่า
2. ย้าย secret ไป environment variable หรือ secret manager
3. ถ้า secret อยู่ใน git history ให้ใช้ `git filter-repo` ล้าง แล้ว force push (ต้องประสานกับทีมก่อน)
4. เรียก API ที่ต้องใช้ secret ผ่าน backend proxy เสมอ ไม่เรียกจาก browser ตรง ๆ

## SPF / DMARC (ข้อ 136)

```
example.com.        TXT  "v=spf1 include:_spf.google.com ~all"
_dmarc.example.com. TXT  "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```
เริ่มที่ `p=none` เก็บรายงานสัก 2–4 สัปดาห์ ดูว่าอีเมลที่ถูกต้องผ่านหมดแล้วค่อยไล่ขึ้น `p=quarantine` → `p=reject` ถ้ากระโดดไป reject เลย อีเมลจริงของบริษัทอาจตกทันที

## SRI สำหรับ script ภายนอก (ข้อ 122)

```html
<script src="https://cdn.jsdelivr.net/npm/lib@1.2.3/dist/lib.min.js"
        integrity="sha384-xxxxx" crossorigin="anonymous"></script>
```
สร้างค่า hash: `curl -s <url> | openssl dgst -sha384 -binary | openssl base64 -A`
ใช้ได้เฉพาะ URL ที่ pin เวอร์ชันแน่นอน — ถ้าใช้ `@latest` จะพังทุกครั้งที่ไลบรารีอัปเดต

## Consent ก่อนยิง pixel (ข้อ 163, PDPA)

โหลด tag ของ Meta/TikTok/GA **หลัง** ผู้ใช้กดยอมรับเท่านั้น ไม่ใช่โหลดไว้ก่อนแล้วค่อยปิด
ถ้าใช้ GTM ให้ตั้ง trigger เป็น consent event และเปิด Consent Mode แทนการวาง tag แบบ All Pages
เก็บ log การให้ความยินยอมพร้อม timestamp และเวอร์ชันนโยบายไว้ด้วย เพราะ PDPA ให้ผู้ควบคุมข้อมูลเป็นฝ่ายพิสูจน์
