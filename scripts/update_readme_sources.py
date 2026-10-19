#!/usr/bin/env python3
"""Synchronize README's complete source list with data/sources.json."""

import argparse
import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SOURCE_DATA = ROOT / "data" / "sources.json"
START = "<!-- source-registry:begin -->"
END = "<!-- source-registry:end -->"

GROUP_LABELS = {
    "discovery": "News, search, and specialist publications",
    "disclosure": "Listed-company disclosures",
    "national": "National authorities",
    "prefecture": "Prefectural governments",
    "government": "Tokyo, special wards, and ordinance-designated cities",
    "transport": "Transport operators and parent companies",
    "it": "IT solution providers and cloud services",
    "retail": "Retailers",
    "distribution": "Distribution and logistics",
    "healthcare": "Healthcare organizations",
    "telecom": "Telecom carriers and Internet service providers",
    "finance": "Banks, insurance, securities, and payments",
    "education": "Universities and education",
    "utilities": "Energy and water utilities",
    "manufacturing": "Manufacturing and pharmaceuticals",
    "wholesale": "Wholesale suppliers",
}
GROUP_ORDER = tuple(GROUP_LABELS)
SECTOR_LABELS = {
    "rail": "Rail and subway",
    "air": "Airlines",
    "airport": "Airports",
    "bus": "Bus operators",
    "ferry": "Ferry and maritime",
    "taxi": "Taxi and dispatch",
    "parent": "Parent and holding companies",
}
SECTOR_ORDER = tuple(SECTOR_LABELS)


def source_line(source):
    return f"- [{source['name']}]({source['url']})"


def render(document):
    grouped = defaultdict(list)
    for source in document["sources"]:
        grouped[source["group"]].append(source)

    lines = [
        START,
        "## Complete source registry",
        "",
        f"The collector currently polls **{document['total']} configured sources**. "
        "This list is generated from [`data/sources.json`](data/sources.json); "
        "run `python3 scripts/update_readme_sources.py` after changing the registry.",
        "",
    ]
    for group in GROUP_ORDER:
        sources = grouped[group]
        lines.extend((
            "<details>",
            f"<summary><strong>{GROUP_LABELS[group]} ({len(sources)})</strong></summary>",
            "",
        ))
        if group == "transport":
            sectors = defaultdict(list)
            for source in sources:
                sectors[source.get("sector")].append(source)
            for sector in SECTOR_ORDER:
                sector_sources = sectors[sector]
                if not sector_sources:
                    continue
                lines.extend((f"#### {SECTOR_LABELS[sector]} ({len(sector_sources)})", ""))
                lines.extend(source_line(source) for source in sector_sources)
                lines.append("")
        else:
            lines.extend(source_line(source) for source in sources)
            lines.append("")
        lines.extend(("</details>", ""))
    lines.append(END)
    return "\n".join(lines)


def updated_readme():
    document = json.loads(SOURCE_DATA.read_text(encoding="utf-8"))
    if document.get("total") != len(document.get("sources", [])):
        raise SystemExit("data/sources.json has an inconsistent total")
    original = README.read_text(encoding="utf-8")
    if START not in original or END not in original:
        raise SystemExit(f"README must contain {START} and {END}")
    before, remainder = original.split(START, 1)
    _, after = remainder.split(END, 1)
    return before + render(document) + after


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if README is out of date")
    args = parser.parse_args()
    expected = updated_readme()
    current = README.read_text(encoding="utf-8")
    if args.check:
        if current != expected:
            raise SystemExit("README source registry is out of date")
        print("README source registry is current")
        return
    if current == expected:
        print("README source registry unchanged")
        return
    README.write_text(expected, encoding="utf-8", newline="\n")
    print("README source registry updated")


if __name__ == "__main__":
    main()
