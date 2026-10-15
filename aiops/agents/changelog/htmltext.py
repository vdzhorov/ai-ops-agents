"""Minimal HTML -> Markdown-ish text for release-note pages (headings, lists, paragraphs, code)."""

import re
from html.parser import HTMLParser


class _ToMarkdown(HTMLParser):
    BLOCK = {"p", "div", "section", "article", "ul", "ol", "table", "tr", "pre", "blockquote", "dl", "dd", "dt"}
    SKIP = {"script", "style", "nav", "footer", "button", "svg"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self._skip_tag: str | None = None  # tag whose subtree is being skipped
        self._skip_depth = 0
        self._list_depth = 0

    def handle_starttag(self, tag, attrs):
        if self._skip_tag:
            if tag == self._skip_tag:
                self._skip_depth += 1
            return
        cls = dict(attrs).get("class") or ""
        if tag in self.SKIP or "headerlink" in cls or "hash-link" in cls:
            self._skip_tag, self._skip_depth = tag, 1
            return
        if tag in ("h1", "h2", "h3", "h4", "h5"):
            self.out.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag == "li":
            self.out.append("\n" + "  " * max(0, self._list_depth - 1) + "- ")
        elif tag in ("ul", "ol"):
            self._list_depth += 1
            self.out.append("\n")
        elif tag == "br":
            self.out.append("\n")
        elif tag == "code":
            self.out.append("`")
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if self._skip_tag:
            if tag == self._skip_tag:
                self._skip_depth -= 1
                if self._skip_depth == 0:
                    self._skip_tag = None
            return
        if tag in ("ul", "ol"):
            self._list_depth = max(0, self._list_depth - 1)
        elif tag == "code":
            self.out.append("`")
        elif tag in ("h1", "h2", "h3", "h4", "h5", "p"):
            self.out.append("\n")

    def handle_data(self, data):
        if not self._skip_tag:
            self.out.append(re.sub(r"\s+", " ", data))


def html_to_md(fragment: str) -> str:
    p = _ToMarkdown()
    p.feed(fragment)
    text = "".join(p.out).replace("​", "").replace("¶", "")
    lines = [l.rstrip() for l in text.splitlines()]
    # "- " followed by a paragraph break inside the <li>: join them
    out: list[str] = []
    for l in lines:
        if out and out[-1].strip() == "-" and l.strip():
            out[-1] = out[-1].rstrip() + " " + l.strip()
        else:
            out.append(l)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(out))
    # tight lists: no blank line between consecutive items
    text = re.sub(r"(\n\s*- [^\n]*)\n\n(?=\s*- )", r"\1\n", text)
    text = re.sub(r"(\n\s*- [^\n]*)\n\n(?=\s*- )", r"\1\n", text)
    return text.strip()
