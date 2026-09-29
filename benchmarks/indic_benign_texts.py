"""Download benign Indian-language text (Wikipedia article introductions) for false-positive tests.

Nine languages: Hindi, Marathi, Bengali, Gujarati, Punjabi, Tamil, Telugu, Kannada, Malayalam. Wikipedia text is
CC BY-SA 4.0, so it is downloaded on demand into benchmarks/data/ (git-ignored), not committed. Random articles, so the
exact texts differ between runs; the count, the languages and the check are what's reproducible.

    python benchmarks/indic_benign_texts.py                 # -> benchmarks/data/indic_benign.jsonl
    python benchmarks/indic_benign_texts.py --per-language 300
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

LANGUAGES = ["hi", "mr", "bn", "gu", "pa", "ta", "te", "kn", "ml"]
# Words the Indian-language rule looks for ("instructions", "ignore"), to fetch hard benign text that uses them.
KEYWORDS = {"hi": ["निर्देश", "अनदेखा"], "mr": ["सूचना", "दुर्लक्ष"], "bn": ["নির্দেশ", "উপেক্ষা"], "gu": ["સૂચના", "અવગણ"],
            "pa": ["ਹਦਾਇਤ", "ਨਜ਼ਰਅੰਦਾਜ਼"], "ta": ["அறிவுறுத்தல்", "புறக்கணி"], "te": ["సూచన", "విస్మరించ"],
            "kn": ["ಸೂಚನೆ", "ನಿರ್ಲಕ್ಷಿಸ"], "ml": ["നിർദ്ദേശ", "അവഗണിക്ക"]}  # fmt: skip
API = "https://{lang}.wikipedia.org/w/api.php?"
HEADERS = {"User-Agent": "guardlayer-benchmarks/1.0 (false-positive test corpus; https://github.com/Lijithvmv/Guard-Layer)"}


def fetch(lang: str, n: int) -> list[str]:
    texts: list[str] = []
    for _ in range(n * 3 // 20 + 5):  # random batches of 20; short or empty intros are skipped
        if len(texts) >= n:
            break
        params = {"action": "query", "generator": "random", "grnnamespace": 0, "grnlimit": 20, "prop": "extracts",
                  "explaintext": 1, "exintro": 1, "format": "json"}  # fmt: skip
        req = urllib.request.Request(API.format(lang=lang) + urllib.parse.urlencode(params), headers=HEADERS)
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    pages = json.load(resp).get("query", {}).get("pages", {})
                break
            except OSError:
                time.sleep(2 ** attempt)
        else:
            continue
        texts += [p["extract"].strip() for p in pages.values() if len(p.get("extract", "").strip()) >= 80]
        time.sleep(0.5)  # be polite to the API
    return texts[:n]


def search(lang: str, word: str, n: int) -> list[str]:
    """Introductions of articles that mention `word` (a harder false-positive test than random articles)."""
    params = {"action": "query", "generator": "search", "gsrsearch": word, "gsrlimit": min(n, 50), "prop": "extracts",
              "explaintext": 1, "exintro": 1, "exlimit": "max", "format": "json"}  # fmt: skip
    req = urllib.request.Request(API.format(lang=lang) + urllib.parse.urlencode(params), headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            pages = json.load(resp).get("query", {}).get("pages", {})
    except OSError:
        return []
    time.sleep(0.5)
    return [p["extract"].strip() for p in pages.values() if len(p.get("extract", "").strip()) >= 80][:n]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--per-language", type=int, default=200)
    p.add_argument("--out", default=str(Path(__file__).parent / "data" / "indic_benign.jsonl"))
    args = p.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    total = 0
    with out.open("w", encoding="utf-8") as fh:
        for lang in LANGUAGES:
            texts = fetch(lang, args.per_language)
            hard = list(dict.fromkeys(t for word in KEYWORDS[lang] for t in search(lang, word, 50)))
            for text in texts:
                fh.write(json.dumps({"text": text, "label": 0, "language": lang, "kind": "random"}, ensure_ascii=False) + "\n")
            for text in hard:
                fh.write(json.dumps({"text": text, "label": 0, "language": lang, "kind": "keyword"}, ensure_ascii=False) + "\n")
            print(f"{lang}: {len(texts)} random + {len(hard)} mentioning its rule words", flush=True)
            total += len(texts) + len(hard)
    print(f"total {total} -> {out} (Wikipedia, CC BY-SA 4.0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
