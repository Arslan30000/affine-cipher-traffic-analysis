#!/usr/bin/env python3
"""Frequency analysis and affine-cipher candidate search for PsycoSupport lab captures."""
from __future__ import annotations
import argparse
import csv
import html
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ENGLISH = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
           0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
           6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
COMMON = set("the be to of and a in that have i it for not on with he as you do at this but his by from they we say her she or an will my one all would there their what so up out if about who get which go me when make can like time no just him know take people into year your good some could them see other than then now look only come its over think also back after use two how our work first well way even new want because these give day most us is are was were has had been being have about i my your today feeling feel worried anxious sad scared angry hopeless lonely confused depressed tired stress stress".split())
WORD_RE = re.compile(r"[A-Za-z]+(?:'[A-Za-z]+)?")

def inv_mod(a: int, m: int = 26) -> int | None:
    for x in range(m):
        if (a*x) % m == 1:
            return x
    return None

def decrypt(text: str, a: int, b: int) -> str:
    ai = inv_mod(a)
    if ai is None:
        raise ValueError(f"a={a} has no inverse modulo 26")
    out = []
    for ch in text:
        upper = ch.upper()
        if upper in ALPHABET:
            y = ord(upper) - 65
            p = (ai * (y - b)) % 26
            decoded = chr(65 + p)
            out.append(decoded if ch.isupper() else decoded.lower())
        else:
            out.append(ch)
    return "".join(out)

def letters(text: str) -> str:
    return "".join(c for c in text.upper() if c in ALPHABET)

def freq_rows(text: str, label: str) -> list[dict[str, object]]:
    s = letters(text); c = Counter(s); n = len(s)
    return [{"sample": label, "letter": ch, "count": c[ch], "percent": round(100*c[ch]/n, 4) if n else 0.0,
             "english_percent": ENGLISH[i]} for i, ch in enumerate(ALPHABET)]

def chi_square(text: str) -> float:
    s = letters(text); n = len(s)
    if not n: return float("inf")
    counts = Counter(s)
    return sum((counts[ch] - n*ENGLISH[i]/100)**2/(n*ENGLISH[i]/100)
               for i, ch in enumerate(ALPHABET) if n*ENGLISH[i]/100 > 0)

def language_score(text: str) -> tuple[float, float, int]:
    """Lower score is better; combine letter distribution with common word evidence."""
    s = letters(text)
    if len(s) < 8: return (float("inf"), float("inf"), 0)
    chi = chi_square(s) / len(s)
    words = [w.lower() for w in WORD_RE.findall(text)]
    evidence = sum(min(len(w), 6) for w in words if w in COMMON)
    # Penalize implausible long alphabetic runs with no common words, but keep the
    # frequency statistic prominent because ciphertexts may omit normal spacing.
    word_penalty = max(0, len(words) - evidence) / max(1, len(words))
    return (chi + 2.0*word_penalty, chi, evidence)

def key_candidates(text: str, limit: int = 12) -> list[dict[str, object]]:
    out=[]
    for a in range(1, 26):
        ai=inv_mod(a)
        if ai is None: continue
        for b in range(26):
            plain=decrypt(text,a,b); score, chi, words=language_score(plain)
            out.append({"a":a,"b":b,"a_inverse":ai,"score":round(score,5),"chi_per_letter":round(chi,5),
                        "common_word_evidence":words,"plaintext_candidate":plain})
    return sorted(out,key=lambda r:(r["score"],r["chi_per_letter"]))[:limit]

def svg_chart(rows: list[dict[str, object]], title: str, path: Path) -> None:
    width,height=900,420; left,bottom,top=55,345,60; plot_h=bottom-top; plot_w=width-left-20
    maxv=max(14.0,max(float(r["percent"]) for r in rows))
    bars=[]
    for i,r in enumerate(rows):
        x=left+i*plot_w/26; slot=plot_w/26; bw=slot/2-2; h=float(r["percent"])/maxv*plot_h
        bars.append(f'<rect x="{x+slot/2:.1f}" y="{bottom-h:.1f}" width="{bw:.1f}" height="{h:.1f}" fill="#2563eb"/><text x="{x+slot/2+bw/2:.1f}" y="{bottom+20}" text-anchor="middle" font-size="12">{r["letter"]}</text>')
    eng=[]
    for i,v in enumerate(ENGLISH):
        x=left+i*plot_w/26; slot=plot_w/26; bw=slot/2-2; h=v/maxv*plot_h
        eng.append(f'<rect x="{x:.1f}" y="{bottom-h:.1f}" width="{bw:.1f}" height="{h:.1f}" fill="#f59e0b" opacity="0.9"/>')
    svg=(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
         f'<rect width="100%" height="100%" fill="white"/><text x="{width/2}" y="30" text-anchor="middle" font-family="Arial" font-size="20">{html.escape(title)}</text>'
         f'<text x="{left}" y="52" font-family="Arial" font-size="12" fill="#2563eb">Captured</text><text x="{left+90}" y="52" font-family="Arial" font-size="12" fill="#b45309">English reference</text>'
         f'<line x1="{left}" y1="{bottom}" x2="{width-15}" y2="{bottom}" stroke="#333"/>'+''.join(eng)+''.join(bars)+'</svg>')
    path.write_text(svg,encoding="utf-8")

def read_csv(path: Path) -> list[dict[str,str]]:
    with path.open(newline="",encoding="utf-8-sig") as f:
        rows=list(csv.DictReader(f))
    required={"id","direction","mood","ciphertext"}
    if not rows: raise SystemExit(f"No capture rows found in {path}.")
    if not required.issubset(rows[0]): raise SystemExit("CSV must contain columns: id,direction,mood,ciphertext")
    for i,r in enumerate(rows,2):
        if not r.get("ciphertext","").strip(): raise SystemExit(f"Row {i} has an empty ciphertext.")
        if r.get("direction","").strip() not in {"client_to_server","server_to_client"}:
            raise SystemExit(f"Row {i}: direction must be client_to_server or server_to_client.")
    return rows

def write_csv(path: Path, rows: Iterable[dict[str,object]]) -> None:
    rows=list(rows)
    if not rows: return
    with path.open("w",newline="",encoding="utf-8") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)

def analyze(source: Path, outdir: Path, top: int) -> None:
    captures=read_csv(source); outdir.mkdir(parents=True,exist_ok=True)
    freqs=[]; cand_rows=[]; notes=[]
    groups=defaultdict(list)
    for row in captures:
        groups[(row["direction"],row.get("mood","").strip().lower())].append(row)
        freqs.extend(freq_rows(row["ciphertext"],row["id"]))
    write_csv(outdir/"frequencies.csv",freqs)
    for (direction,mood),items in sorted(groups.items()):
        label=direction+(f"_{mood}" if mood else "")
        combined="\n".join(x["ciphertext"] for x in items)
        rows=freq_rows(combined,label); svg_chart(rows,f"Letter frequency: {label}",outdir/f"frequency_{re.sub('[^A-Za-z0-9_-]','_',label)}.svg")
        candidates=key_candidates(combined,top)
        for rank,item in enumerate(candidates,1):
            cand_rows.append({"group":label,"rank":rank,**item})
        notes.append(f"### {label}\n\nSamples: {len(items)}; alphabetic characters: {len(letters(combined))}. Top affine candidates follow in `key_candidates.csv`. Automated scoring is a ranking aid; validate keys against every capture and show the arithmetic in the report.\n")
    write_csv(outdir/"key_candidates.csv",cand_rows)
    (outdir/"analysis_notes.md").write_text("# Analysis notes\n\n"+"\n".join(notes)+"\n",encoding="utf-8")

def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,default=Path("data/ciphertexts.csv"))
    parser.add_argument("--output",type=Path,default=Path("results"))
    parser.add_argument("--top",type=int,default=12,help="number of candidate keys to retain per direction/mood group")
    args=parser.parse_args()
    analyze(args.input,args.output,max(1,args.top))

if __name__=="__main__": main()


