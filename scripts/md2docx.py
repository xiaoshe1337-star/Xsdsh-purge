"""把 使用教程.md 转成 DOCX（保留标题层级、表格、代码块、列表）。"""
import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Cm

SRC = Path(sys.argv[1])
DST = Path(sys.argv[2])

CJK = "Microsoft YaHei"
MONO = "Consolas"


def set_run_font(run, name=CJK, size=None, bold=None, color=None):
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = rpr.makeelement(qn("w:rFonts"), {})
        rpr.append(rfonts)
    rfonts.set(qn("w:ascii"), name)
    rfonts.set(qn("w:hAnsi"), name)
    rfonts.set(qn("w:eastAsia"), name)  # 关键：中日韩字形
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if color is not None:
        run.font.color.rgb = RGBColor(*color)


INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`)")

# 表格识别：允许对齐标记（:---:），只要含 | 且不是引用/代码
TBL_ROW = re.compile(r"^\s*\|.*\|\s*$")
TBL_SEP = re.compile(r"^\s*\|[\s:|-]+\|\s*$")


def is_table_row(s):
    return bool(TBL_ROW.match(s))


def is_table_sep(s):
    """分隔行：只由 | - : 空格 组成，且至少一个 -。"""
    return bool(TBL_SEP.match(s)) and "-" in s


def split_row(s):
    return [c.strip() for c in s.strip().strip("|").split("|")]


def make_ordered_num(p, n):
    """手工给有序列表编号：写入文本 + 用悬挂缩进对齐，避开 Word 编号续接问题。"""
    p.style = doc.styles["List Paragraph"]
    r = p.add_run(f"{n}.\t")
    set_run_font(r, CJK, 10.5, True, (0x33, 0x33, 0x33))
    p.paragraph_format.left_indent = Cm(0.85)
    p.paragraph_format.first_line_indent = Cm(-0.85)


def add_inline(par, text, base_size=10.5, base_bold=False):
    """处理 **粗体** 和 `代码` 两种行内标记。"""
    text = text.replace("&nbsp;", " ")
    for piece in INLINE.split(text):
        if not piece:
            continue
        if piece.startswith("**") and piece.endswith("**") and len(piece) > 4:
            r = par.add_run(piece[2:-2])
            set_run_font(r, CJK, base_size, True)
        elif piece.startswith("`") and piece.endswith("`") and len(piece) > 2:
            r = par.add_run(piece[1:-1])
            set_run_font(r, MONO, base_size - 0.5, None, (0xC0, 0x39, 0x2B))
        else:
            r = par.add_run(piece)
            set_run_font(r, CJK, base_size, base_bold)


doc = Document()

# 页面与正文样式
sec = doc.sections[0]
sec.left_margin = sec.right_margin = Cm(2.2)
sec.top_margin = sec.bottom_margin = Cm(2.0)
normal = doc.styles["Normal"]
normal.font.name = CJK
normal.font.size = Pt(10.5)
normal._element.rPr.rFonts.set(qn("w:eastAsia"), CJK)
normal.paragraph_format.space_after = Pt(4)
normal.paragraph_format.line_spacing = 1.25

for lvl in range(1, 5):
    st = doc.styles[f"Heading {lvl}"]
    st.font.name = CJK
    st._element.rPr.rFonts.set(qn("w:eastAsia"), CJK)
    st.font.color.rgb = RGBColor(0x1A, 0x1A, 0x1A)

lines = SRC.read_text(encoding="utf-8").splitlines()
i = 0
first_h1 = True

while i < len(lines):
    ln = lines[i]
    stripped = ln.strip()

    # ---- 代码块 / mermaid ----
    if stripped.startswith("```"):
        lang = stripped[3:].strip()
        i += 1
        buf = []
        while i < len(lines) and not lines[i].strip().startswith("```"):
            buf.append(lines[i])
            i += 1
        i += 1  # 跳过结束围栏
        if lang == "mermaid":
            p = doc.add_paragraph()
            r = p.add_run("［流程图 · 源码见同目录 使用教程.md 的 mermaid 代码块］")
            set_run_font(r, CJK, 9, True, (0x55, 0x55, 0x55))
            p.paragraph_format.left_indent = Cm(0.5)
            for l in buf:
                q = doc.add_paragraph()
                rr = q.add_run(l)
                set_run_font(rr, MONO, 8.5, None, (0x44, 0x44, 0x44))
                q.paragraph_format.left_indent = Cm(0.8)
                q.paragraph_format.space_after = Pt(0)
        else:
            for l in buf:
                p = doc.add_paragraph()
                r = p.add_run(l if l else " ")
                set_run_font(r, MONO, 9)
                p.paragraph_format.left_indent = Cm(0.4)
                p.paragraph_format.space_after = Pt(0)
                p.paragraph_format.line_spacing = 1.0
            doc.add_paragraph().paragraph_format.space_after = Pt(2)
        continue

    # ---- 表格 ----
    if is_table_row(ln) and i + 1 < len(lines) and is_table_sep(lines[i + 1]):
        rows = []
        while i < len(lines) and is_table_row(lines[i]):
            if not is_table_sep(lines[i]):
                rows.append(split_row(lines[i]))
            i += 1
        if not rows:
            continue
        # 列数取众数，避免个别单元格多出 | 时算错
        from collections import Counter
        ncol = Counter(len(r) for r in rows).most_common(1)[0][0]
        tbl = doc.add_table(rows=0, cols=ncol)
        tbl.style = "Table Grid"
        tbl.alignment = WD_TABLE_ALIGNMENT.LEFT
        for ri, row in enumerate(rows):
            cells = tbl.add_row().cells
            for ci in range(ncol):
                txt = row[ci] if ci < len(row) else ""
                cell = cells[ci]
                cell.text = ""
                par = cell.paragraphs[0]
                par.paragraph_format.space_after = Pt(0)
                add_inline(par, txt, 9.5, ri == 0)
        doc.add_paragraph().paragraph_format.space_after = Pt(2)
        continue

    # ---- 标题 ----
    m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
    if m:
        lvl = len(m.group(1))
        text = m.group(2).strip().replace("**", "")
        if lvl == 1 and first_h1:
            doc.add_heading(text, level=0)
            first_h1 = False
        else:
            doc.add_heading(text, level=min(lvl, 4))
        i += 1
        continue

    # ---- 分隔线 ----
    if stripped in ("---", "***", "___"):
        p = doc.add_paragraph()
        r = p.add_run("─" * 46)
        set_run_font(r, CJK, 8, None, (0xBB, 0xBB, 0xBB))
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p.paragraph_format.space_after = Pt(6)
        i += 1
        continue

    # ---- 引用块：剥掉 > 前缀后按普通 markdown 处理（内部可能含表格/列表） ----
    if stripped.startswith(">"):
        buf = []
        while i < len(lines) and lines[i].lstrip().startswith(">"):
            raw = lines[i].lstrip()
            raw = raw[1:]
            if raw.startswith(" "):
                raw = raw[1:]
            buf.append(raw)
            i += 1
        lines[i:i] = buf + [""]
        continue

    # ---- 列表 ----
    m = re.match(r"^(\s*)([-*]|\d+\.)\s+(.*)$", ln)
    if m:
        indent, bullet, text = m.group(1), m.group(2), m.group(3)
        depth = len(indent) // 2
        prev = lines[i - 1] if i > 0 else ""
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if bullet in "-*":
            try:
                p = doc.add_paragraph(style="List Bullet")
            except KeyError:
                p = doc.add_paragraph()
            add_inline(p, text, 10.5)
            p.paragraph_format.left_indent = Cm(0.6 + 0.55 * depth)
            p.paragraph_format.first_line_indent = Cm(-0.35)
        else:
            # 手工编号：新列表（上一行/下一行不是有序项的同级）就重置为 1
            prev_m = re.match(r"^\s*(\d+)\.\s", prev)
            same = bool(prev_m) and len(prev) - len(prev.lstrip()) == len(indent)
            counter = (int(prev_m.group(1)) + 1) if same else 1
            p = doc.add_paragraph()
            make_ordered_num(p, counter)
            add_inline(p, text, 10.5)
        i += 1
        continue

    # ---- 空行 ----
    if not stripped:
        i += 1
        continue

    # ---- 正文 ----
    p = doc.add_paragraph()
    add_inline(p, stripped, 10.5)
    i += 1

doc.save(DST)
print(f"saved: {DST}")
print(f"paragraphs: {len(doc.paragraphs)}  tables: {len(doc.tables)}")
