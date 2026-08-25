#!/usr/bin/env python3
"""Render findings.json into a single-file, fully offline interactive HTML report.

No CDN, no fonts, no analytics — the output opens from disk on an air-gapped
machine. Each finding accepts a status and a comment, persisted to localStorage,
exportable as JSON, and maskable before sharing outside the organisation.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium",
             "low": "Low", "info": "Info"}

CSS = """
:root{--bg:#fff;--fg:#1a1a2e;--muted:#5c6370;--border:#d8dce3;--accent:#7b2ff7;
--card:#f8f9fb;--code:#f0f2f5;--critical:#b3001b;--high:#c2680a;--medium:#8a6d00;
--low:#3a6ea5;--info:#5c6370;--ok:#0a7d33}
@media(prefers-color-scheme:dark){:root{--bg:#14161c;--fg:#e4e6eb;--muted:#9aa1ad;
--border:#333945;--accent:#b98cff;--card:#1a1e26;--code:#21252e;--critical:#ff6b6b;
--high:#ffb454;--medium:#ffd166;--low:#7fb3e8;--info:#9aa1ad;--ok:#5dd48a}}
*{box-sizing:border-box}
body{margin:0;font-family:"Hiragino Sans","Noto Sans JP","Yu Gothic UI",Meiryo,sans-serif;
background:var(--bg);color:var(--fg);line-height:1.6;font-size:15px}
.wrap{max-width:1180px;margin:0 auto;padding:22px 18px 70px}
h1{font-size:1.4rem;border-bottom:3px solid var(--accent);padding-bottom:9px;margin:6px 0 4px}
.meta{color:var(--muted);font-size:.84rem;margin-bottom:14px}
.bar{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0}
.pill{border:1px solid var(--border);border-radius:20px;padding:5px 14px;font-size:.85rem;
background:var(--card);cursor:pointer;user-select:none}
.pill.on{background:var(--accent);color:#fff;border-color:var(--accent)}
.count{display:inline-block;min-width:1.6em;text-align:center;font-weight:700}
.gapbox{border:1px solid var(--high);background:var(--card);border-radius:8px;padding:10px 14px;
margin:12px 0;font-size:.87rem}
.f{border:1px solid var(--border);border-left:6px solid var(--info);border-radius:0 8px 8px 0;
margin:12px 0;padding:12px 15px;background:var(--card)}
.f.critical{border-left-color:var(--critical)}.f.high{border-left-color:var(--high)}
.f.medium{border-left-color:var(--medium)}.f.low{border-left-color:var(--low)}
.f h3{margin:0 0 4px;font-size:1rem}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 8px;font-size:.74rem}
.tag{border:1px solid var(--border);border-radius:10px;padding:1px 8px;color:var(--muted)}
.tag.sev{font-weight:700;color:#fff;border:none}
.tag.sev.critical{background:var(--critical)}.tag.sev.high{background:var(--high)}
.tag.sev.medium{background:var(--medium);color:#1a1a2e}.tag.sev.low{background:var(--low)}
.tag.sev.info{background:var(--info)}
.tag.warn{border-color:var(--high);color:var(--high);font-weight:700}
dl{margin:8px 0 0;font-size:.89rem}
dt{font-weight:700;color:var(--muted);font-size:.78rem;margin-top:7px}
dd{margin:2px 0 0}
.ctl{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:10px;
padding-top:10px;border-top:1px dashed var(--border)}
select,textarea,input{font:inherit;background:var(--bg);color:var(--fg);
border:1px solid var(--border);border-radius:6px;padding:5px 8px}
textarea{width:100%;min-height:48px;resize:vertical;margin-top:6px}
code{font-family:ui-monospace,Consolas,monospace;background:var(--code);padding:1px 5px;border-radius:4px;font-size:.86em}
button{font:inherit;background:var(--card);color:var(--fg);border:1px solid var(--border);
border-radius:6px;padding:6px 14px;cursor:pointer}
button:hover{border-color:var(--accent)}
.masked .mask{background:var(--fg);color:transparent;border-radius:3px;user-select:none}
.masked .mask *{color:transparent}
h2{font-size:1.1rem;margin:26px 0 8px;border-left:5px solid var(--accent);padding-left:10px}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin:8px 0}
th{background:var(--card);text-align:left;padding:7px 9px;border-bottom:2px solid var(--border)}
td{padding:7px 9px;border-bottom:1px solid var(--border);vertical-align:middle}
.hint{font-size:.82rem;color:var(--muted)}
footer{margin-top:36px;padding-top:14px;border-top:1px solid var(--border);
color:var(--muted);font-size:.8rem}
@media print{.bar,.ctl button,#tools{display:none}.f{break-inside:avoid}}
"""

JS = """
const KEY='nhi-posture-'+document.body.dataset.reportId;
const known=new Set([...document.querySelectorAll('.f')].map(e=>e.dataset.id));
const sanitize=o=>{const out=Object.create(null);
  for(const k of Object.keys(o||{})){if(known.has(k))out[k]=o[k];}return out;};
const load=()=>{try{return sanitize(JSON.parse(localStorage.getItem(KEY)||'{}'))}catch(e){return Object.create(null)}};
let state=load();
const save=()=>localStorage.setItem(KEY,JSON.stringify(state));
document.querySelectorAll('.f').forEach(el=>{
  const id=el.dataset.id, s=state[id]||{};
  const sel=el.querySelector('select'), ta=el.querySelector('textarea');
  if(s.status)sel.value=s.status;
  if(s.comment)ta.value=s.comment;
  sel.addEventListener('change',()=>{state[id]={...(state[id]||{}),status:sel.value};save();applyFilter()});
  ta.addEventListener('input',()=>{state[id]={...(state[id]||{}),comment:ta.value};save()});
});
const filters={sev:new Set(),hideDone:false};
document.querySelectorAll('.pill[data-sev]').forEach(p=>p.addEventListener('click',()=>{
  const v=p.dataset.sev;
  filters.sev.has(v)?filters.sev.delete(v):filters.sev.add(v);
  p.classList.toggle('on');applyFilter();
}));
function applyFilter(){
  document.querySelectorAll('.f').forEach(el=>{
    const st=(state[el.dataset.id]||{}).status||'open';
    let show=filters.sev.size===0||filters.sev.has(el.dataset.sev);
    if(filters.hideDone&&(st==='done'||st==='accepted'||st==='na'))show=false;
    el.style.display=show?'':'none';
  });
  const n=[...document.querySelectorAll('.f')].filter(e=>e.style.display!=='none').length;
  document.getElementById('shown').textContent=n;
}
document.getElementById('hideDone').addEventListener('change',e=>{
  filters.hideDone=e.target.checked;applyFilter();});
document.getElementById('exportBtn').addEventListener('click',()=>{
  const rows=[...document.querySelectorAll('.f')].map(el=>({
    id:el.dataset.id,ruleId:el.dataset.rule,severity:el.dataset.sev,
    resource:el.dataset.resource,
    status:(state[el.dataset.id]||{}).status||'open',
    comment:(state[el.dataset.id]||{}).comment||''}));
  const ta=document.getElementById('io');ta.value=JSON.stringify(rows,null,2);
  ta.scrollIntoView({behavior:'smooth'});
});
document.getElementById('importBtn').addEventListener('click',()=>{
  try{
    const rows=JSON.parse(document.getElementById('io').value);
    if(!Array.isArray(rows))throw new Error('配列ではありません');
    let applied=0,skipped=0;
    rows.forEach(r=>{
      if(r&&typeof r.id==='string'&&known.has(r.id)){
        state[r.id]={status:String(r.status||''),comment:String(r.comment||'')};applied++;
      }else{skipped++;}
    });
    save();
    if(skipped)alert(applied+' 件を反映しました。'+skipped+' 件はこのレポートに存在しない ID のため無視しました。');
    location.reload();
  }catch(e){alert('JSON を解釈できません: '+e.message)}
});
document.getElementById('maskBtn').addEventListener('click',()=>
  document.body.classList.toggle('masked'));
applyFilter();
"""

STATUSES = [("open", "未対応"), ("triage", "トリアージ中"), ("wip", "対応中"),
            ("accepted", "リスク受容"), ("done", "対応済み"), ("na", "対象外")]


def esc(value):
    return html.escape(str(value)) if value is not None else ""


def esc_masked(value, tokens):
    """Escape text, then wrap every sensitive token so masking actually hides it."""
    text = esc(value)
    for token in sorted({t for t in tokens if t and len(str(t)) >= 4}, key=len, reverse=True):
        needle = esc(token)
        if needle and needle in text:
            text = text.replace(needle, f'<span class="mask">{needle}</span>')
    return text


def render(report, title):
    findings = report.get("findings", [])
    summary = report.get("summary", {})
    report_id = report.get("generatedAt", "report").replace(":", "").replace("-", "")

    pills = "".join(
        f'<span class="pill" data-sev="{s}"><span class="count">{summary.get(s, 0)}</span> {SEV_LABEL[s]}</span>'
        for s in SEV_ORDER)

    gaps = report.get("coverageGaps", [])
    gapbox = ""
    if gaps:
        scope_tokens = [s.get("id") for s in report.get("scopes", [])]
        items = "".join(
            f"<li><code>{esc_masked(g.get('area'), scope_tokens)}</code> — {esc(g.get('reason'))}"
            f"{(': ' + esc_masked(g.get('detail'), scope_tokens)) if g.get('detail') else ''}</li>"
            for g in gaps)
        gapbox = (f'<div class="gapbox"><strong>証跡を取得できなかった領域が {len(gaps)} 件あります。'
                  f'未取得を「問題なし」と読み替えないでください。</strong><ul>{items}</ul></div>')

    owasp = report.get("owaspSummary") or {}
    owaspbox = ""
    if owasp:
        cells = "".join(
            f'<tr><td><strong>{esc(k)}</strong></td>'
            f'<td><span class="tag sev {v["worst"]}">{SEV_LABEL.get(v["worst"], v["worst"])}</span></td>'
            f'<td>{v["count"]}</td><td><code>{esc(", ".join(v["rules"]))}</code></td></tr>'
            for k, v in owasp.items())
        owaspbox = ('<h2>OWASP NHI Top 10 別の検出状況</h2>'
                    '<table><thead><tr><th>カテゴリ</th><th>最悪</th><th>件数</th>'
                    f'<th>該当ルール</th></tr></thead><tbody>{cells}</tbody></table>'
                    '<p class="hint">ここに現れないカテゴリは「問題なし」ではなく、'
                    '本パックに該当ルールが無いか、証跡が取得できていない可能性がある。'
                    'NHI3(サードパーティ)と NHI9(再利用)はクラウドネイティブでは'
                    '原理的に検出しきれない領域である。</p>')

    resolved = report.get("resolved") or []
    deltabox = ""
    if report.get("baseline"):
        new_n = sum(1 for f in findings if f.get("state") == "new")
        rows = "".join(f"<li><code>{esc(x.get('ruleId'))}</code> {esc(x.get('title'))} — "
                       f"<code>{esc(x.get('resourceKey'))}</code></li>" for x in resolved)
        deltabox = (f'<h2>前回との差分</h2><p>新規 <strong>{new_n}</strong> 件 / '
                    f'継続 <strong>{len(findings) - new_n}</strong> 件 / '
                    f'解消 <strong>{len(resolved)}</strong> 件</p>'
                    + (f'<details><summary>解消した指摘</summary><ul>{rows}</ul></details>'
                       if rows else '')
                    + '<p class="hint">解消は「検出されなくなった」ことを意味する。証跡が'
                      '取得できなくなった場合も解消に見えるため、未取得領域と併せて読むこと。</p>')

    suppressed = report.get("suppressed") or []
    supbox = ""
    if suppressed:
        rows = "".join(f"<li><code>{esc(x.get('ruleId'))}</code> — "
                       f"<code>{esc(x.get('resourceKey'))}</code> "
                       f"(除外パターン <code>{esc(x.get('pattern'))}</code>)</li>"
                       for x in suppressed)
        supbox = (f'<div class="gapbox"><strong>ルール例外により {len(suppressed)} 件を'
                  f'抑止しました。</strong>抑止は握りつぶしではありません。妥当性を定期的に'
                  f'見直してください。<ul>{rows}</ul></div>')

    blocks = []
    for f in findings:
        sev = f.get("severity", "info")
        opts = "".join(f'<option value="{v}">{l}</option>' for v, l in STATUSES)
        tags = [f'<span class="tag sev {sev}">{SEV_LABEL.get(sev, sev)}</span>',
                f'<span class="tag">{esc(f.get("ruleId"))}</span>']
        for o in f.get("owasp", []) or []:
            tags.append(f'<span class="tag">OWASP {esc(o)}</span>')
        if f.get("cloud"):
            tags.append(f'<span class="tag">{esc(f["cloud"]).upper()}</span>')
        if f.get("evidenceIncomplete"):
            tags.append('<span class="tag warn">証跡不足 / 確度 低</span>')
        if f.get("state") == "new":
            tags.append('<span class="tag warn">新規</span>')
        secrets = [f.get("resourceName"), f.get("scopeId"), f.get("resourceKey")]
        rows = [("検出内容", esc_masked(f.get("message"), secrets)),
                ("あるべき状態", esc(f.get("expected"))),
                ("対処", esc_masked(f.get("remediation"), secrets)),
                ("確認方法", esc(f.get("validation")))]
        if f.get("caveat"):
            rows.append(("注意", esc(f.get("caveat"))))
        dl = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows if v)
        blocks.append(f'''<div class="f {sev}" data-id="{esc(f.get('id'))}" data-sev="{sev}"
 data-rule="{esc(f.get('ruleId'))}" data-resource="{esc(f.get('resourceKey') or f.get('resourceName'))}">
<h3>{esc(f.get('title'))}</h3>
<div class="tags">{''.join(tags)}</div>
<div style="font-size:.85rem;color:var(--muted)">対象: <code class="mask">{esc(f.get('resourceName'))}</code>
 <span style="opacity:.7">({esc(f.get('resourceType'))})</span></div>
<dl>{dl}</dl>
<div class="ctl"><label>ステータス <select>{opts}</select></label></div>
<textarea placeholder="コメント / 判断理由 / 対応期限"></textarea>
</div>''')

    scopes = ", ".join(f"{s.get('cloud')}:{s.get('id')}" for s in report.get("scopes", [])) or "—"
    packs = ", ".join(f"{p.get('name')} v{p.get('version')}" for p in report.get("packs", []))

    return f'''<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)}</title><style>{CSS}</style></head>
<body data-report-id="{esc(report_id)}"><div class="wrap">
<h1>{esc(title)}</h1>
<div class="meta">生成 {esc(report.get('generatedAt'))} / 証跡 {esc(report.get('dbGeneratedAt'))}<br>
対象スコープ: {esc(scopes)} &nbsp;·&nbsp; ルールパック: {esc(packs)} &nbsp;·&nbsp;
表示中 <span id="shown">0</span> / {len(findings)} 件</div>
{gapbox}
{supbox}
{deltabox}
{owaspbox}
<div class="bar">{pills}
<label class="pill"><input type="checkbox" id="hideDone"> 対応済み・受容を隠す</label></div>
<div id="tools" class="bar">
<button id="exportBtn">JSON 書き出し</button>
<button id="importBtn">JSON 読み込み</button>
<button id="maskBtn">公開用マスク切替</button>
<button onclick="window.print()">印刷 / PDF</button></div>
<textarea id="io" placeholder="ここに JSON が出力されます / 貼り付けて読み込みます"></textarea>
{''.join(blocks) or '<p>検出事項はありません。ただし証跡カバレッジを必ず確認してください。</p>'}
<footer>入力内容はこのブラウザの localStorage にのみ保存されます。共有前に「公開用マスク」で
リソース名を伏せてください。<strong>マスクは 4 文字以上の識別子(リソース名・アカウント ID・
リソースキー)を対象とします。短い名称や本文中の固有名詞は伏せられない場合があるため、
外部共有前に目視で確認してください。</strong>判定は収集時点の証跡に基づきます。</footer>
</div><script>{JS}</script></body></html>'''


def main(argv=None):
    ap = argparse.ArgumentParser(description="Render NHI findings into an offline HTML report.")
    ap.add_argument("findings", help="findings.json from scan.py")
    ap.add_argument("-o", "--output",
                    default=f"nhi-posture-report-{datetime.now(timezone.utc):%Y%m%d}.html")
    ap.add_argument("--title", default="NHI ポスチャ評価レポート")
    args = ap.parse_args(argv)

    try:
        with open(args.findings, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        print(f"error: cannot read findings {args.findings}: {exc}", file=sys.stderr)
        return 1
    if "findings" not in report:
        print(f"error: {args.findings} is not a findings report (no 'findings' key)",
              file=sys.stderr)
        return 1
    Path(args.output).write_text(render(report, args.title), encoding="utf-8")
    print(f"wrote {args.output} ({len(report.get('findings', []))} findings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
