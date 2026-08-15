# -*- coding: utf-8 -*-
"""รายงาน HTML ไฟล์เดียว — เปิดจากเครื่องได้เลย

ทำไมไฟล์เดียวและไม่มี asset ภายนอก: รายงานนี้บอกว่าระบบของเจ้าของเว็บพังตรงไหน
มันไม่ควรต้องเรียก CDN, ไม่ควรถูกอัปขึ้นที่ไหน และต้องเปิดอ่านได้แม้ไม่มีเน็ต
ส่ง `file://` ให้ทีมทางแชทได้ทันที
"""
import datetime
import html
import json

RISK_COLOR = {
    "Critical": ("#7f1d1d", "#fee2e2", "#fecaca"),
    "High": ("#7c2d12", "#ffedd5", "#fed7aa"),
    "Medium": ("#713f12", "#fef9c3", "#fde68a"),
    "Low": ("#14532d", "#dcfce7", "#bbf7d0"),
}
STATUS_COLOR = {
    "ไม่ผ่าน": ("#991b1b", "#fee2e2"),
    "ผ่าน": ("#166534", "#dcfce7"),
    "ยังไม่ตรวจ": ("#475569", "#f1f5f9"),
}

CSS = """
*{box-sizing:border-box}
body{margin:0;background:#f1f5f9;color:#0f172a;
 font-family:-apple-system,"Segoe UI","Noto Sans Thai","Sarabun",system-ui,sans-serif;
 line-height:1.55}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
header h1{margin:0 0 4px;font-size:22px;letter-spacing:-.01em}
header p{margin:0;color:#64748b;font-size:13px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:18px;margin-top:16px}
h2{font-size:15px;margin:0 0 12px}
.tiles{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-top:16px}
.tile{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:14px 16px}
.tile .n{font-size:28px;font-weight:700;line-height:1.1;font-variant-numeric:tabular-nums}
.tile .l{font-size:12px;color:#64748b;margin-top:2px}
.bar{display:flex;height:10px;border-radius:99px;overflow:hidden;margin:10px 0 14px;background:#e2e8f0}
.bar span{display:block}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:#64748b;
 padding:8px 10px;border-bottom:1px solid #e2e8f0;position:sticky;top:0;background:#fff}
td{padding:10px;border-bottom:1px solid #f1f5f9;vertical-align:top}
tr:last-child td{border-bottom:0}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;white-space:nowrap}
.id{color:#94a3b8;font-variant-numeric:tabular-nums;font-size:12px}
.ev{color:#475569;font-size:12px;margin-top:3px;word-break:break-word}
.finding{border:1px solid #e2e8f0;border-left-width:4px;border-radius:12px;padding:12px 14px;margin-bottom:10px;background:#fff}
.finding .t{font-weight:600}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
button.f{border:1px solid #cbd5e1;background:#fff;border-radius:99px;padding:5px 13px;font-size:12.5px;
 cursor:pointer;font-family:inherit;color:#334155}
button.f[aria-pressed="true"]{background:#0f172a;color:#fff;border-color:#0f172a}
input[type=search]{flex:1;min-width:190px;border:1px solid #cbd5e1;border-radius:9px;padding:7px 11px;
 font-size:13px;font-family:inherit}
.note{background:#fffbeb;border:1px solid #fde68a;color:#78350f;border-radius:12px;padding:12px 14px;
 margin-top:16px;font-size:13px}
.cat{font-size:12px;color:#64748b}
footer{margin-top:28px;color:#94a3b8;font-size:12px;text-align:center}
@media print{
 body{background:#fff}.controls{display:none}.card,.tile,.finding{break-inside:avoid}
}
"""

JS = """
const rows = Array.from(document.querySelectorAll('#checklist tbody tr'));
const btns = Array.from(document.querySelectorAll('button.f'));
const box  = document.getElementById('q');
let filter = 'all';

function apply(){
  const q = box.value.trim().toLowerCase();
  let shown = 0;
  for (const tr of rows){
    const okStatus = filter === 'all' || tr.dataset.status === filter;
    const okText   = !q || tr.textContent.toLowerCase().includes(q);
    const show = okStatus && okText;
    tr.hidden = !show;
    if (show) shown++;
  }
  document.getElementById('count').textContent = shown + ' รายการ';
}
btns.forEach(b => b.addEventListener('click', () => {
  filter = b.dataset.filter;
  btns.forEach(x => x.setAttribute('aria-pressed', String(x === b)));
  apply();
}));
box.addEventListener('input', apply);
apply();
"""


def _esc(v):
    return html.escape(str(v if v is not None else ""))


def _pill(text, fg, bg):
    return f'<span class="pill" style="color:{fg};background:{bg}">{_esc(text)}</span>'


def render(data, generated_at=None):
    """data มาจาก prepare() ใน build_report.py"""
    scan, domain = data["scan"], data["domain"]
    rows, fails = data["rows"], data["fails"]
    meta = scan.get("meta", {})

    counts = {k: sum(1 for r in rows if r["status"] == k) for k in ("ไม่ผ่าน", "ผ่าน", "ยังไม่ตรวจ")}
    total = len(rows) or 1
    by_risk = {k: sum(1 for f in fails if f["risk"] == k) for k in RISK_COLOR}

    tiles = [
        ("ไม่ผ่าน", counts["ไม่ผ่าน"], "#b91c1c"),
        ("ผ่าน", counts["ผ่าน"], "#15803d"),
        ("ยังไม่ตรวจ", counts["ยังไม่ตรวจ"], "#475569"),
        ("รวมทั้งหมด", len(rows), "#0f172a"),
    ]
    tiles_html = "".join(
        f'<div class="tile"><div class="n" style="color:{c}">{n}</div><div class="l">{_esc(l)}</div></div>'
        for l, n, c in tiles
    )

    bar = "".join(
        f'<span style="width:{counts[k]/total*100:.4f}%;background:{c}" title="{_esc(k)} {counts[k]}"></span>'
        for k, c in (("ไม่ผ่าน", "#ef4444"), ("ผ่าน", "#22c55e"), ("ยังไม่ตรวจ", "#cbd5e1"))
    )

    risk_line = " · ".join(f"{k} {by_risk[k]}" for k in ("Critical", "High", "Medium", "Low") if by_risk[k])

    if fails:
        findings = "".join(
            '<div class="finding" style="border-left-color:{border}">'
            '<div><span class="id">#{id}</span> {pill} <span class="cat">{cat}</span></div>'
            '<div class="t">{item}</div>'
            '<div class="ev">{ev}</div>'
            '<div class="ev">วิธีตรวจซ้ำ: {method}</div>'
            "</div>".format(
                border=RISK_COLOR[f["risk"]][2], id=f["id"],
                pill=_pill(f["risk"], *RISK_COLOR[f["risk"]][:2]),
                cat=_esc(f["category"]), item=_esc(f["item"]),
                ev=_esc(f["evidence"] or "—"), method=_esc(f["method"]),
            )
            for f in fails
        )
    else:
        findings = '<p style="color:#15803d;margin:0">ไม่พบข้อที่ไม่ผ่านจากการตรวจอัตโนมัติ</p>'

    body_rows = "".join(
        '<tr data-status="{st}"><td class="id">{id}</td><td><div>{item}</div>'
        '<div class="cat">{cat}</div>{ev}</td><td>{risk}</td><td>{stpill}</td></tr>'.format(
            st=_esc(r["status"]), id=r["id"], item=_esc(r["item"]), cat=_esc(r["category"]),
            ev=f'<div class="ev">{_esc(r["evidence"])}</div>' if r["evidence"] else "",
            risk=_pill(r["risk"], *RISK_COLOR[r["risk"]][:2]),
            stpill=_pill(r["status"], *STATUS_COLOR.get(r["status"], ("#475569", "#f1f5f9"))),
        )
        for r in rows
    )

    # The honest headline. A run that reached nothing, or one where a whole
    # class of check could not be answered, must say so above the numbers —
    # not leave the reader to infer it from a big "ยังไม่ตรวจ" count.
    notes = []
    if meta.get("reachable") is False:
        notes.append("เว็บไม่ตอบสนองบนพอร์ต 443 จากเครื่องที่รันสแกน — ข้อที่เกี่ยวกับตัวเว็บทั้งหมดจึงเป็น "
                     "“ยังไม่ตรวจ” ไม่ใช่ “ผ่าน” ผลที่เชื่อได้ในรายงานนี้คือส่วนที่ตรวจจากโค้ดในเครื่องเท่านั้น")
    if (scan.get("path_baseline") or {}).get("soft_404"):
        notes.append("เว็บตอบ 200 ให้ path ที่ไม่มีอยู่จริง (soft 404) — ใช้ status code ตัดสินว่าไฟล์หลุดไม่ได้ "
                     "ข้อ 30–41 จึงเป็น “ยังไม่ตรวจ”")
    if (scan.get("tls") or {}).get("protocols_unknown"):
        notes.append("openssl บนเครื่องที่รันสแกนไม่ยอมต่อ TLS รุ่นเก่า จึงยังไม่ได้ถามเซิร์ฟเวอร์จริง — "
                     "ยืนยันข้อ 1 ด้วย SSL Labs หรือ nmap --script ssl-enum-ciphers")
    notes_html = "".join(f'<div class="note">{_esc(n)}</div>' for n in notes)

    stamp = generated_at or datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!doctype html>
<html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>รายงานความปลอดภัย — {_esc(domain)}</title>
<style>{CSS}</style></head><body><div class="wrap">

<header>
  <h1>รายงานผลตรวจความปลอดภัย — {_esc(domain)}</h1>
  <p>สแกนเมื่อ {_esc(meta.get("scanned_at", "-"))} · {_esc(meta.get("scanner", "web-security-scan"))} ·
     เช็คลิสต์ {len(rows)} รายการ</p>
</header>

<div class="tiles">{tiles_html}</div>
<div class="bar">{bar}</div>
{notes_html}

<div class="card">
  <h2>ข้อที่ไม่ผ่าน เรียงตามความเสียหายจริง{f" ({_esc(risk_line)})" if risk_line else ""}</h2>
  {findings}
</div>

<div class="card">
  <h2>เช็คลิสต์ทั้งหมด</h2>
  <div class="controls">
    <button class="f" data-filter="all" aria-pressed="true">ทั้งหมด</button>
    <button class="f" data-filter="ไม่ผ่าน" aria-pressed="false">ไม่ผ่าน</button>
    <button class="f" data-filter="ยังไม่ตรวจ" aria-pressed="false">ยังไม่ตรวจ</button>
    <button class="f" data-filter="ผ่าน" aria-pressed="false">ผ่าน</button>
    <input type="search" id="q" placeholder="ค้นหา เช่น CSP, cookie, PDPA">
    <span class="cat" id="count"></span>
  </div>
  <table id="checklist">
    <thead><tr><th style="width:52px">ข้อ</th><th>รายการ</th>
      <th style="width:92px">ความเสี่ยง</th><th style="width:104px">สถานะ</th></tr></thead>
    <tbody>{body_rows}</tbody>
  </table>
</div>

<footer>ไฟล์นี้อ่านได้ออฟไลน์ ไม่เรียกทรัพยากรภายนอก · สร้างเมื่อ {_esc(stamp)}</footer>
</div><script>{JS}</script></body></html>
"""
