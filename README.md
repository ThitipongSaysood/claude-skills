# claude-skills

Skill สำหรับ [Claude Code](https://claude.com/claude-code) — ใช้เองและแชร์ให้คนอื่นใช้ได้

| Skill | ทำอะไร |
|---|---|
| [`web-security-scan`](skills/web-security-scan/) | ตรวจความปลอดภัยเว็บที่คุณเป็นเจ้าของ ตามเช็คลิสต์ 189 ข้อ (TLS, security headers, ข้อมูลรั่วไหล, cookie, DNS, dependency, PDPA) แล้วออกรายงานเป็นหน้าเว็บ HTML หรือไฟล์ Excel |

## วิธีติดตั้ง

### แบบที่ 1 — คัดลอกเข้าเครื่อง

```bash
git clone https://github.com/ThitipongSaysood/claude-skills.git
cp -R claude-skills/skills/web-security-scan ~/.claude/skills/
```

เปิด Claude Code ใหม่ แล้วพิมพ์ `/web-security-scan` หรือถามเป็นภาษาคนว่า "ตรวจความปลอดภัยเว็บให้หน่อย"

### แบบที่ 2 — ใช้กับทั้งทีมผ่าน repo ของโปรเจกต์

ก๊อปไปไว้ที่ `.claude/skills/` ในโปรเจกต์แล้ว commit — ทุกคนที่ clone โปรเจกต์นั้นจะได้ skill ไปด้วย

### แบบที่ 3 — ตัวจัดการ skill ที่ดึงจาก GitHub

ถ้าใช้เครื่องมือที่เก็บ `skills-lock.json` ชี้มาที่ repo นี้ได้เลย โครงสร้างเป็นแบบมาตรฐาน
`skills/<ชื่อ>/SKILL.md` เหมือน `anthropics/skills` และ `obra/superpowers`

```json
{
  "source": "ThitipongSaysood/claude-skills",
  "sourceType": "github",
  "skillPath": "skills/web-security-scan/SKILL.md"
}
```

## หลักที่ยึดตอนเขียน skill พวกนี้

**ตรวจไม่ได้ ไม่เท่ากับ ผ่าน** — เขียนไว้ตัวโต ๆ เพราะเป็นบั๊กที่เจอจริงตอนรีวิว `web-security-scan`
รอบแรก: `timeout` ไม่มีบน macOS สคริปต์เลยเก็บค่า TLS ไม่ได้ ผลลัพธ์ว่างเปล่าถูกนับเป็น "ผ่าน"
ในข้อที่เสี่ยงที่สุดของเช็คลิสต์ รายงานที่บอกว่าปลอดภัยทั้งที่ไม่เคยตรวจ อันตรายกว่าไม่มีรายงานเลย

**เครื่องมือที่ทำงานผิดต้องดังกว่าเครื่องมือที่ทำงานถูก** — สคริปต์ที่ทำงานพลาดแล้วเงียบ
คือสคริปต์ที่หลอกคนใช้ ทุกจุดที่เก็บข้อมูลไม่ได้ต้องพูดออกมาว่าเก็บไม่ได้ พร้อมบอกวิธีตรวจด้วยมือแทน

## License

MIT
