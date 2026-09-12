"""Retrieval over the SOC knowledge base.

Hybrid lexical + dense retrieval, fused with Reciprocal Rank Fusion.

Lexical matters more here than it usually does: security text is full of exact
tokens an embedding blurs — T1003.001, lsass.exe, 4625, rundll32.exe. BM25 nails
those. Dense retrieval catches the paraphrase cases BM25 misses ("dumped
credentials from memory" vs "OS Credential Dumping"). Fusing both beats either,
and BM25 alone still works if the embedding model is unavailable, so retrieval
never becomes a hard dependency on a model download.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
KB_DIR = BASE_DIR / "data" / "kb"
CORPUS_PATH = KB_DIR / "corpus.json"
EMBED_PATH = KB_DIR / "embeddings.npy"
EMBED_MODEL = "BAAI/bge-small-en-v1.5"

# Security identifiers must survive tokenisation intact: T1003.001, lsass.exe,
# 4688, powershell.exe. Splitting on dots would destroy sub-technique ids.
_TOKEN = re.compile(r"[a-z0-9]+(?:[.\-_][a-z0-9]+)*")

_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "are", "was", "were",
    "for", "on", "by", "with", "as", "at", "from", "that", "this", "it", "be",
    "can", "may", "which", "has", "have", "had", "will", "been", "their", "its",
}


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN.findall(text.lower()) if t not in _STOP and len(t) > 1]


class BM25:
    """Okapi BM25. ~50 lines, no dependency beyond numpy."""

    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.doc_count = len(docs)
        self.doc_lens = np.array([len(d) for d in docs], dtype=np.float32)
        self.avg_len = float(self.doc_lens.mean()) if self.doc_count else 0.0

        self.term_freqs: list[Counter] = [Counter(d) for d in docs]
        df: Counter = Counter()
        for tf in self.term_freqs:
            df.update(tf.keys())

        # BM25+ idf floor, so a term in most documents cannot score negative.
        self.idf = {
            term: math.log(1 + (self.doc_count - n + 0.5) / (n + 0.5))
            for term, n in df.items()
        }

        self.postings: dict[str, list[int]] = {}
        for i, tf in enumerate(self.term_freqs):
            for term in tf:
                self.postings.setdefault(term, []).append(i)

    def score(self, query_tokens: list[str]) -> tuple[np.ndarray, np.ndarray, int]:
        """Score documents, and report how many distinct query terms each matched.

        Coverage matters as much as score here. A chunk that matches one rare
        term can outscore a chunk that matches three common ones, which is how
        an unrelated technique ends up presented as grounding. Callers use
        coverage to require genuine overlap rather than a single lucky hit.
        """
        scores = np.zeros(self.doc_count, dtype=np.float32)
        coverage = np.zeros(self.doc_count, dtype=np.int16)

        # Coverage is judged against every distinct term the caller asked for,
        # including ones absent from the vocabulary: a query where only one term
        # of several is even known is a weak query, and its single match is not
        # evidence.
        distinct = list(dict.fromkeys(query_tokens))
        for term in distinct:
            idf = self.idf.get(term)
            if idf is None:
                continue
            for i in self.postings[term]:
                freq = self.term_freqs[i][term]
                norm = 1 - self.b + self.b * (self.doc_lens[i] / (self.avg_len or 1))
                scores[i] += idf * (freq * (self.k1 + 1)) / (freq + self.k1 * norm)
                coverage[i] += 1

        return scores, coverage, len(distinct)


# A chunk needs real lexical overlap to be worth citing. Without a floor, BM25
# always returns its best 5 chunks even for a query with no genuine match, and
# the model would then cite them as grounding. Retrieving nothing is the correct
# outcome for an unrecognised incident: ground rule 1 turns it into UNKNOWN.
MIN_LEXICAL = 3.0


def _relevance_floor(scores) -> float:
    """Cut-off below which a match is noise rather than evidence."""
    best = max(scores, default=0.0)
    if best < MIN_LEXICAL:
        return float("inf")  # nothing here is relevant; return no grounding
    return max(MIN_LEXICAL, 0.25 * best)


def _rrf(rankings: list[list[int]], k: int = 60) -> dict[int, float]:
    """Reciprocal Rank Fusion — combines rankings without score calibration."""
    fused: dict[int, float] = {}
    for ranking in rankings:
        for rank, idx in enumerate(ranking):
            fused[idx] = fused.get(idx, 0.0) + 1.0 / (k + rank + 1)
    return fused


class KnowledgeBase:
    """Loads the corpus and answers retrieval queries."""

    def __init__(self, corpus_path: Path | None = None, use_dense: bool = True):
        self.corpus_path = corpus_path or CORPUS_PATH
        if not self.corpus_path.exists():
            raise FileNotFoundError(
                f"Knowledge base not built: {self.corpus_path}. "
                "Run scripts/build_kb.py first."
            )
        self.chunks: list[dict[str, Any]] = json.loads(
            self.corpus_path.read_text(encoding="utf-8")
        )
        self._by_id = {c["id"]: c for c in self.chunks}

        searchable = [f"{c.get('title','')} {c.get('text','')}" for c in self.chunks]
        self.bm25 = BM25([tokenize(s) for s in searchable])

        self.embeddings: np.ndarray | None = None
        self._encoder = None
        if use_dense:
            self._load_dense()

        # Retrieval telemetry (#11): separates "retrieval missed" from
        # "model ignored what it was given" when a verdict comes out wrong.
        self.stats = {"queries": 0, "empty_results": 0, "dense_used": 0}

    def _load_dense(self) -> None:
        if not EMBED_PATH.exists():
            return
        try:
            from sentence_transformers import SentenceTransformer

            self.embeddings = np.load(EMBED_PATH)
            if len(self.embeddings) != len(self.chunks):
                print("[!] embeddings out of sync with corpus; using BM25 only")
                self.embeddings = None
                return
            self._encoder = SentenceTransformer(EMBED_MODEL)
        except Exception as exc:  # noqa: BLE001 - degrade to lexical, never fail
            print(f"[!] dense retrieval unavailable ({exc}); using BM25 only")
            self.embeddings = None
            self._encoder = None

    @property
    def has_dense(self) -> bool:
        return self.embeddings is not None and self._encoder is not None

    def _rank(self, query: str, depth: int) -> tuple[dict[int, float], np.ndarray]:
        """Fused ranking for one query. Returns {idx: rrf_score} and raw lexical."""
        lexical, coverage, n_terms = self.bm25.score(tokenize(query))

        # With enough query terms to judge by, demand overlap on at least two of
        # them. A single-term hit is a coincidence, not grounding.
        min_coverage = 2 if n_terms >= 3 else 1
        eligible = [
            i for i in np.argsort(-lexical)[:depth]
            if lexical[i] > 0 and coverage[i] >= min_coverage
        ]
        rankings = [eligible]

        if self.has_dense:
            vec = self._encoder.encode([query], normalize_embeddings=True)[0]
            dense = self.embeddings @ vec
            rankings.append(list(np.argsort(-dense)[:depth]))
            self.stats["dense_used"] += 1

        return _rrf(rankings), lexical

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        self.stats["queries"] += 1

        fused, lexical = self._rank(query, depth=top_k * 4)
        ordered = sorted(fused.items(), key=lambda kv: -kv[1])[:top_k]
        floor = _relevance_floor([lexical[i] for i, _ in ordered])

        results = []
        for idx, score in ordered:
            if lexical[idx] < floor:
                continue
            chunk = dict(self.chunks[idx])
            # `score` fuses the rankings and is only comparable within one query;
            # `lexical` is the absolute BM25 strength and is comparable across
            # queries, which is what structured retrieval needs to merge on.
            chunk["score"] = round(float(score), 5)
            chunk["lexical"] = round(float(lexical[idx]), 4)
            results.append(chunk)

        if not results:
            self.stats["empty_results"] += 1
        return results

    def search_structured(
        self,
        event_ids: list[str] | None = None,
        processes: list[str] | None = None,
        terms: list[str] | None = None,
        hints: list[str] | None = None,
        top_k: int = 6,
    ) -> list[dict[str, Any]]:
        """Compound retrieval keyed on what the incident actually contains.

        Querying with raw log text retrieves noise. Querying with the identifiers
        that carry meaning — event ids, process names, extracted terms — is what
        makes retrieval land on the right technique.
        """
        # Weighted sub-queries. Event-id lookups are kept deliberately terse:
        # boilerplate like "windows security log" matches every event chunk
        # equally, which drowns the ATT&CK techniques that actually explain the
        # incident. Behavioural terms describe what happened and so carry the
        # most weight; event ids just anchor the log-format reference.
        queries: list[tuple[str, float]] = []
        for eid in event_ids or []:
            queries.append((f"event id {eid}", 1.0))
        for proc in processes or []:
            queries.append((f"{proc} abuse execution", 1.5))
        if terms:
            queries.append((" ".join(terms), 2.5))
        for hint in hints or []:
            queries.append((hint, 0.75))

        if not queries:
            return []

        # Fuse every sub-query into one ranking rather than taking each one's
        # top hits and merging by score. Scores from different queries are not
        # comparable, so merging on them would let a weak chunk that happened to
        # top a junk sub-query outrank a strong chunk that placed second in a
        # good one. RRF across all sub-queries rewards chunks that rank well
        # repeatedly, which is exactly the consensus signal we want.
        self.stats["queries"] += 1
        combined: dict[int, float] = {}
        lexical_best: dict[int, float] = {}

        for q, weight in queries:
            fused, lexical = self._rank(q, depth=top_k * 3)
            for idx, score in fused.items():
                combined[idx] = combined.get(idx, 0.0) + weight * score
                lexical_best[idx] = max(lexical_best.get(idx, 0.0), float(lexical[idx]))

        if not combined:
            self.stats["empty_results"] += 1
            return []

        ordered = sorted(combined.items(), key=lambda kv: -kv[1])
        floor = _relevance_floor(lexical_best.values())

        results = []
        for idx, score in ordered:
            if lexical_best.get(idx, 0.0) < floor:
                continue
            chunk = dict(self.chunks[idx])
            chunk["score"] = round(float(score), 5)
            chunk["lexical"] = round(lexical_best.get(idx, 0.0), 4)
            results.append(chunk)
            if len(results) >= top_k:
                break

        if not results:
            self.stats["empty_results"] += 1
        return results

    def get(self, chunk_id: str) -> dict[str, Any] | None:
        return self._by_id.get(chunk_id)


_KB: KnowledgeBase | None = None


def get_kb(force_reload: bool = False) -> KnowledgeBase:
    global _KB
    if _KB is None or force_reload:
        _KB = KnowledgeBase()
    return _KB
