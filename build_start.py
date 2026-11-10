"""
build_start.py — generate the self-contained START.html from index.html + static/*.

    python build_start.py        (or: make build)

START.html is a BUILD OUTPUT — edit index.html / static/* and rebuild instead.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent


def build() -> str:
    html = (ROOT / "index.html").read_text(encoding="utf-8")
    read = lambda rel: (ROOT / rel).read_text(encoding="utf-8")

    html = re.sub(r'<link rel="stylesheet" href="([^"]+)"\s*/?>',
                  lambda m: "<style>\n" + read(m.group(1)) + "\n</style>", html)

    def inline_js(m):
        code = read(m.group(1)).replace("</script", "<\\/script")
        return "<script>\n" + code + "\n</script>"

    html = re.sub(r'<script src="([^"]+)"></script>', inline_js, html)
    assert 'src="static/' not in html and 'href="static/' not in html, "unresolved asset link"
    return html


if __name__ == "__main__":
    out = build()
    (ROOT / "START.html").write_text(out, encoding="utf-8")
    print(f"START.html built ({len(out.splitlines())} lines, {len(out)//1024} KB)")
