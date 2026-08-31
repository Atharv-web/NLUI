#web_search.py
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import quote_plus, urlparse

from orchestrator.runtime_models import PLANNER_MODEL

def _get_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


BASE_DIR        = _get_base_dir()
API_CONFIG_PATH = BASE_DIR / "config" / "api_keys.json"


def _get_api_key() -> str:
    with open(API_CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)["gemini_api_key"]


def _gemini_search(query: str) -> str:
    from google import genai

    client   = genai.Client(api_key=_get_api_key())
    response = client.models.generate_content(
        model=PLANNER_MODEL,
        contents=query,
        config={"tools": [{"google_search": {}}]},
    )

    text = ""
    for part in response.candidates[0].content.parts:
        if hasattr(part, "text") and part.text:
            text += part.text

    text = text.strip()
    if not text:
        raise ValueError("Gemini returned an empty response.")
    return text


def _ddg_search(query: str, max_results: int = 6) -> list[dict]:
    try:
        from ddgs import DDGS
    except ImportError:
        from duckduckgo_search import DDGS

    results = []
    with DDGS() as ddgs:
        for r in ddgs.text(query, max_results=max_results):
            results.append({
                "title":   r.get("title",  ""),
                "snippet": r.get("body",   ""),
                "url":     r.get("href",   ""),
            })
    return results


def _ddg_news(query: str, max_results: int = 8) -> list[dict]:
    """DDG news search — returns actual articles, not website homepages."""
    try:
        from ddgs import DDGS
    except ImportError:
        from duckduckgo_search import DDGS

    results = []
    try:
        with DDGS() as ddgs:
            for r in ddgs.news(query, max_results=max_results):
                results.append({
                    "title":   r.get("title",  ""),
                    "snippet": r.get("body",   ""),
                    "url":     r.get("url",    ""),
                    "source":  r.get("source", ""),
                })
    except Exception as e:
        # A normal text search returns section pages such as Reuters World or
        # Google News topics. Those are not articles, so let the dedicated RSS
        # fallback handle this failure instead.
        print(f"[WebSearch] DDG news() failed ({e})")
    return results


_NEWS_LANDING_TITLES = (
    "world news | latest top stories",
    "google news - world",
    "world | latest news & updates",
    "breaking news, latest news",
)
_NEWS_LANDING_PATHS = {
    "", "/", "/news", "/world", "/world/", "/international", "/latest",
}


def _clean_text(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", value or "")
    return " ".join(html.unescape(without_tags).split())


def _is_article_result(result: dict) -> bool:
    title = _clean_text(str(result.get("title", "")))
    url = str(result.get("url", "")).strip()
    if not title or not url:
        return False

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False

    title_lower = title.casefold()
    if any(pattern in title_lower for pattern in _NEWS_LANDING_TITLES):
        return False

    path_lower = parsed.path.casefold()
    if path_lower in _NEWS_LANDING_PATHS:
        return False
    if parsed.netloc.casefold().endswith("news.google.com") and path_lower.startswith("/topics/"):
        return False
    return True


def _clean_news_results(results: list[dict], limit: int = 5) -> list[dict]:
    cleaned = []
    seen_urls = set()
    seen_titles = set()
    for result in results:
        if not _is_article_result(result):
            continue

        title = _clean_text(str(result.get("title", "")))
        url = str(result.get("url", "")).strip()
        title_key = title.casefold()
        url_key = url.rstrip("/").casefold()
        if title_key in seen_titles or url_key in seen_urls:
            continue

        cleaned.append({
            "title": title,
            "snippet": _clean_text(str(result.get("snippet", ""))),
            "url": url,
            "source": _clean_text(str(result.get("source", ""))),
        })
        seen_titles.add(title_key)
        seen_urls.add(url_key)
        if len(cleaned) >= limit:
            break
    return cleaned


def _google_news_rss(query: str, max_results: int = 8) -> list[dict]:
    """Fetch current article headlines from Google News RSS."""
    import requests

    if "world news" in query.casefold():
        url = (
            "https://news.google.com/rss/headlines/section/topic/WORLD"
            "?hl=en-IN&gl=IN&ceid=IN:en"
        )
    else:
        search_terms = f"{query} when:2d"
        url = (
            "https://news.google.com/rss/search"
            f"?q={quote_plus(search_terms)}&hl=en-IN&gl=IN&ceid=IN:en"
        )
    response = requests.get(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; MARK-L/1.0)"},
        timeout=8,
    )
    response.raise_for_status()
    root = ET.fromstring(response.content)

    results = []
    for item in root.findall(".//item"):
        title = _clean_text(item.findtext("title", default=""))
        article_url = (item.findtext("link", default="") or "").strip()
        source = _clean_text(item.findtext("source", default=""))
        if source and title.casefold().endswith(f" - {source}".casefold()):
            title = title[:-(len(source) + 3)].strip()
        results.append({
            "title": title,
            "snippet": "",
            "url": article_url,
            "source": source,
        })
        if len(results) >= max_results:
            break
    return results


def _format_ddg(query: str, results: list[dict]) -> str:
    if not results:
        return f"No results found for: {query}"

    lines = [f"Search results for: {query}\n"]
    for i, r in enumerate(results, 1):
        if r.get("title"):   lines.append(f"{i}. {r['title']}")
        if r.get("snippet"): lines.append(f"   {r['snippet']}")
        if r.get("url"):     lines.append(f"   Source: {r['url']}")
        lines.append("")
    return "\n".join(lines).strip()


def _format_news(query: str, results: list[dict]) -> str:
    articles = _clean_news_results(results)
    if not articles:
        return f"No news found for: {query}"

    lines = [
        f"{i}. [{article['title']}]({article['url']})"
        for i, article in enumerate(articles, 1)
    ]
    return "\n".join(lines).strip()


# ── Briefing helper ────────────────────────────────────────────────────────────

def _gemini_headlines(n: int = 5) -> tuple[list[str], str]:
    """
    Fetches current headlines via Gemini grounded search.
    Optimised for speed: minimal prompt + strict token cap.
    Returns (headline_list, raw_text_for_display).
    """
    import re
    from google import genai

    client = genai.Client(api_key=_get_api_key())
    response = client.models.generate_content(
            model=PLANNER_MODEL,
        contents=f"Current world news: {n} headlines. Numbered list, titles only.",
        config={"tools": [{"google_search": {}}]},
    )

    raw = ""
    for part in response.candidates[0].content.parts:
        if hasattr(part, "text") and part.text:
            raw += part.text

    headlines = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        # Only accept lines that begin with a number — skips preamble/closing sentences
        if not re.match(r'^[\d]+[.\)\-]', line):
            continue
        clean = re.sub(r'^[\d]+[.\)\-]\s*', '', line)
        clean = re.sub(r'^\*+\s*',          '', clean).strip()
        if clean and len(clean) > 10:
            headlines.append(clean)

    return headlines[:n], raw.strip()


# ── Modes ──────────────────────────────────────────────────────────────────────

def _search(query: str) -> str:
    """Default search — Gemini grounded, DDG fallback."""
    try:
        return _gemini_search(query)
    except Exception as e:
        print(f"[WebSearch] ⚠️ Gemini failed ({e}) — trying DDG...")
        results = _ddg_search(query)
        return _format_ddg(query, results)


def _news(query: str) -> str:
    """
    Runs two article-specific news sources in parallel.
    Generic web search is deliberately excluded because it returns publisher
    homepages and topic pages instead of current articles.
    """
    import threading

    news_query = query if query else "world news today"

    result_box  = [None]   # first valid result lands here
    lock        = threading.Lock()
    done_evt    = threading.Event()
    failures    = [0]

    def _store(results: list[dict]) -> None:
        formatted = _format_news(news_query, results)
        if results and not formatted.startswith("No news found"):
            with lock:
                if result_box[0] is None:
                    result_box[0] = formatted
            done_evt.set()
        else:
            with lock:
                failures[0] += 1
                if failures[0] >= 2:   # both failed — unblock caller
                    done_evt.set()

    def _try_rss():
        try:
            _store(_google_news_rss(news_query, max_results=8))
        except Exception as e:
            print(f"[WebSearch] Google News RSS failed ({e})")
            _store([])

    def _try_ddg():
        try:
            _store(_ddg_news(news_query, max_results=8))
        except Exception as e:
            print(f"[WebSearch] DDG news failed ({e})")
            _store([])

    threading.Thread(target=_try_rss, daemon=True).start()
    threading.Thread(target=_try_ddg,    daemon=True).start()

    done_evt.wait(timeout=10.0)
    return result_box[0] or f"No news found for: {news_query}"


def _research(query: str) -> str:
    """
    Deep dive — asks Gemini for a comprehensive answer with context.
    Falls back to a wider DDG fetch.
    """
    research_query = (
        f"Comprehensive, detailed explanation of: {query}. "
        "Include background context, key facts, current state, and important nuances."
    )
    try:
        return _gemini_search(research_query)
    except Exception as e:
        print(f"[WebSearch] ⚠️ Research Gemini failed ({e}) — DDG fallback...")
        results = _ddg_search(query, max_results=10)
        return _format_ddg(query, results)


def _price(query: str) -> str:
    """Product price lookup — searches for current market prices."""
    price_query = f"current price of {query} — how much does it cost today"
    try:
        return _gemini_search(price_query)
    except Exception as e:
        print(f"[WebSearch] ⚠️ Price Gemini failed ({e}) — DDG fallback...")
        results = _ddg_search(f"{query} price buy", max_results=6)
        return _format_ddg(query, results)


def _compare(items: list[str], aspect: str) -> str:
    query = (
        f"Compare {', '.join(items)} in terms of {aspect}. "
        "Give specific facts and data."
    )
    try:
        return _gemini_search(query)
    except Exception as e:
        print(f"[WebSearch] ⚠️ Gemini compare failed: {e} — falling back to DDG")

    all_results: dict[str, list] = {}
    for item in items:
        try:
            all_results[item] = _ddg_search(f"{item} {aspect}", max_results=3)
        except Exception:
            all_results[item] = []

    lines = [f"Comparison — {aspect.upper()}", "─" * 40]
    for item in items:
        lines.append(f"\n▸ {item}")
        for r in all_results.get(item, [])[:2]:
            if r.get("snippet"):
                lines.append(f"  • {r['snippet']}")
            if r.get("url"):
                lines.append(f"    {r['url']}")
    return "\n".join(lines)


# ── Public entry point ─────────────────────────────────────────────────────────

def web_search(
    parameters:     dict,
    response=None,
    player=None,
    session_memory=None,
) -> str:
    params = parameters or {}
    query  = params.get("query", "").strip()
    mode   = params.get("mode",  "search").lower().strip()
    items  = params.get("items", [])
    aspect = params.get("aspect", "general").strip() or "general"

    if not query and not items:
        return "Please provide a search query."

    if items and mode not in ("compare",):
        mode = "compare"

    if player:
        player.write_log(f"[Search:{mode}] {query or ', '.join(items)}")

    print(f"[WebSearch] 🔍 mode={mode!r}  query={query!r}")

    try:
        if mode == "compare" and items:
            return _compare(items, aspect)
        if mode == "news":
            return _news(query)
        if mode == "research":
            return _research(query)
        if mode == "price":
            return _price(query)
        return _search(query)

    except Exception as e:
        print(f"[WebSearch] ❌ All backends failed: {e}")
        return f"Search failed: {e}"
