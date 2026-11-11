"""Tiện ích dựng báo cáo Word bằng python-docx."""
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

FONT = "Times New Roman"
NAVY = RGBColor(0x1F, 0x3A, 0x5F)


def _set_font(run, size=None, bold=None, italic=None, name=FONT, color=None):
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts"); rpr.append(rf)
    for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        rf.set(qn(a), name)
    if size:
        run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if italic is not None:
        run.font.italic = italic
    if color is not None:
        run.font.color.rgb = color


def shade(cell, hex_fill):
    tcPr = cell._element.get_or_add_tcPr()
    shd = OxmlElement("w:shd"); shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), hex_fill)
    tcPr.append(shd)


class Doc:
    def __init__(self):
        self.d = Document()
        s = self.d.sections[0]
        s.page_height, s.page_width = Cm(29.7), Cm(21.0)
        s.left_margin, s.right_margin, s.top_margin, s.bottom_margin = Cm(3.0), Cm(2.0), Cm(2.5), Cm(2.5)
        st = self.d.styles["Normal"]
        st.font.name = FONT; st.font.size = Pt(12)
        st.element.rPr.rFonts.set(qn("w:eastAsia"), FONT)
        st.paragraph_format.line_spacing = 1.25
        st.paragraph_format.space_after = Pt(4)
        for lvl, sz in ((1, 15), (2, 13), (3, 12)):
            h = self.d.styles[f"Heading {lvl}"]
            h.font.name = FONT; h.font.size = Pt(sz); h.font.bold = True; h.font.color.rgb = NAVY if lvl < 3 else RGBColor(0, 0, 0)
            h.element.rPr.rFonts.set(qn("w:eastAsia"), FONT); h.element.rPr.rFonts.set(qn("w:ascii"), FONT); h.element.rPr.rFonts.set(qn("w:hAnsi"), FONT)
            h.paragraph_format.space_before = Pt(14 if lvl == 1 else 10); h.paragraph_format.space_after = Pt(5)
            h.paragraph_format.keep_with_next = True
        self.fig_n = self.tab_n = 0
        self.headings = []

    # ---- text ----
    def h(self, text, lvl=1, page_break=False):
        if page_break:
            self.d.add_page_break()
        p = self.d.add_heading(text, level=lvl)
        for r in p.runs:
            _set_font(r, size={1: 15, 2: 13, 3: 12}[lvl], bold=True, color=NAVY if lvl < 3 else RGBColor(0, 0, 0))
        if lvl <= 2:
            self.headings.append((lvl, text))
        return p

    def p(self, text="", bold=False, italic=False, align="j", size=None, after=None, indent=True):
        para = self.d.add_paragraph()
        para.alignment = {"j": WD_ALIGN_PARAGRAPH.JUSTIFY, "c": WD_ALIGN_PARAGRAPH.CENTER, "l": WD_ALIGN_PARAGRAPH.LEFT, "r": WD_ALIGN_PARAGRAPH.RIGHT}[align]
        if indent and align == "j":
            para.paragraph_format.first_line_indent = Cm(0.9)
        if after is not None:
            para.paragraph_format.space_after = Pt(after)
        self._runs(para, text, bold, italic, size)
        return para

    def _runs(self, para, text, bold=False, italic=False, size=None):
        # **đậm** và `mã` inline
        import re
        for tok in re.split(r"(\*\*[^*]+\*\*|`[^`]+`|(?<![\w*])\*[^*\s][^*]*\*(?![\w*]))", text):
            if not tok:
                continue
            if tok.startswith("**"):
                r = para.add_run(tok[2:-2]); _set_font(r, size, True, italic)
            elif tok.startswith("*") and tok.endswith("*") and len(tok) > 2:
                r = para.add_run(tok[1:-1]); _set_font(r, size, bold, True)
            elif tok.startswith("`"):
                r = para.add_run(tok[1:-1]); _set_font(r, (size or 12) - 1.5, bold, italic, name="Courier New")
            else:
                r = para.add_run(tok); _set_font(r, size, bold, italic)

    def bullets(self, items, style="List Bullet"):
        for it in items:
            para = self.d.add_paragraph(style=style)
            para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            para.paragraph_format.space_after = Pt(2)
            self._runs(para, it)

    def numbered(self, items):
        self.bullets(items, "List Number")

    def code(self, text, size=8.5):
        for line in text.strip("\n").split("\n"):
            para = self.d.add_paragraph()
            para.paragraph_format.line_spacing = 1.0; para.paragraph_format.space_after = Pt(0)
            para.paragraph_format.left_indent = Cm(0.4)
            pPr = para._element.get_or_add_pPr(); shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto"); shd.set(qn("w:fill"), "F2F2F2"); pPr.append(shd)
            r = para.add_run(line if line else " "); _set_font(r, size, name="Courier New")
        self.d.add_paragraph().paragraph_format.space_after = Pt(2)

    # ---- figure/table ----
    def figure(self, path, caption, width_cm=15.0):
        self.fig_n += 1
        para = self.d.add_paragraph(); para.alignment = WD_ALIGN_PARAGRAPH.CENTER; para.paragraph_format.keep_with_next = True
        para.add_run().add_picture(path, width=Cm(width_cm))
        c = self.d.add_paragraph(); c.alignment = WD_ALIGN_PARAGRAPH.CENTER
        self._runs(c, f"**Hình {self.fig_n}.** {caption}", italic=False, size=11)

    def table(self, header, rows, widths=None, caption=None, size=10, shade_rows=None, align_center_cols=()):
        if caption:
            self.tab_n += 1
            c = self.d.add_paragraph(); c.alignment = WD_ALIGN_PARAGRAPH.CENTER; c.paragraph_format.keep_with_next = True
            self._runs(c, f"**Bảng {self.tab_n}.** {caption}", size=11)
        t = self.d.add_table(rows=1, cols=len(header)); t.style = "Table Grid"; t.alignment = WD_TABLE_ALIGNMENT.CENTER
        for i, h in enumerate(header):
            cell = t.rows[0].cells[i]; cell.text = ""; shade(cell, "1F3A5F")
            r = cell.paragraphs[0].add_run(h); _set_font(r, size, True, color=RGBColor(255, 255, 255))
            cell.paragraphs[0].paragraph_format.space_after = Pt(0)
        trPr = t.rows[0]._tr.get_or_add_trPr(); th = OxmlElement("w:tblHeader"); th.set(qn("w:val"), "true"); trPr.append(th)
        for ri, row in enumerate(rows):
            cells = t.add_row().cells
            for i, v in enumerate(row):
                cells[i].text = ""
                para = cells[i].paragraphs[0]; para.paragraph_format.space_after = Pt(0); para.paragraph_format.line_spacing = 1.05
                if i in align_center_cols:
                    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
                self._runs(para, str(v), size=size)
                if ri % 2 == 1:
                    shade(cells[i], "EDF2F7")
            trPr = t.rows[-1]._tr.get_or_add_trPr(); cs = OxmlElement("w:cantSplit"); cs.set(qn("w:val"), "true"); trPr.append(cs)
        if widths:
            t.autofit = False
            for row in t.rows:
                for i, w in enumerate(widths):
                    row.cells[i].width = Cm(w)
        self.d.add_paragraph().paragraph_format.space_after = Pt(2)
        return t

    # ---- page number ----
    def footer_page_numbers(self):
        s = self.d.sections[0]
        s.different_first_page_header_footer = True
        para = s.footer.paragraphs[0]; para.alignment = WD_ALIGN_PARAGRAPH.CENTER
        for kind, txt in (("begin", None), (None, "PAGE"), ("end", None)):
            r = para.add_run(); _set_font(r, 10)
            if kind:
                fc = OxmlElement("w:fldChar"); fc.set(qn("w:fldCharType"), kind); r._r.append(fc)
            else:
                it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = txt; r._r.append(it)
        hp = s.header.paragraphs[0]; hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        r = hp.add_run("Đồ án An toàn thông tin – Đề tài 19: Đánh giá chữ ký số cho phần mềm và tài liệu điện tử"); _set_font(r, 9, italic=True, color=RGBColor(0x55, 0x55, 0x55))

    def page_break(self):
        self.d.add_page_break()

    def save(self, path):
        self.d.save(path)
