"""Local evidence store with retrieval provenance and integrity checks.

The store is deliberately dependency-free. It ranks text with a transparent BM25-style
lexical scorer; retrieval scores are relevance signals, not truth or calibrated probabilities.
Only ingest sources that your application is allowed to store. The JSON database contains the
source text and should be protected like any other potentially sensitive data store.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

_TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)
_SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _tokens(text: str) -> list[str]:
    return [token.lower() for token in _TOKEN_RE.findall(text)]


def _safe_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    result = dict(metadata or {})
    try:
        json.dumps(result, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError("metadata must contain only JSON-serializable values") from exc
    return result


def _make_chunks(text: str, chunk_size: int, overlap: int) -> list[tuple[str, int, int]]:
    """Split text while retaining exact source offsets for each chunk."""
    chunks: list[tuple[str, int, int]] = []
    start = 0
    text_length = len(text)
    while start < text_length:
        end = min(start + chunk_size, text_length)
        if end < text_length:
            min_boundary = start + int(chunk_size * 0.60)
            paragraph = text.rfind("\n\n", min_boundary, end)
            newline = text.rfind("\n", min_boundary, end)
            space = text.rfind(" ", min_boundary, end)
            boundary = max(paragraph, newline, space)
            if boundary > start:
                end = boundary
        if end <= start:
            end = min(start + chunk_size, text_length)
        chunk_text = text[start:end]
        if chunk_text.strip():
            chunks.append((chunk_text, start, end))
        if end >= text_length:
            break
        next_start = max(start + 1, end - overlap)
        # Prefer a nearby token boundary to avoid cutting words in the overlap region.
        if overlap and next_start < text_length:
            candidate = text.find(" ", next_start, min(text_length, next_start + 40))
            if candidate != -1 and candidate < end:
                next_start = candidate + 1
        start = next_start
    return chunks


@dataclass(frozen=True)
class EvidenceChunk:
    evidence_id: str
    source_id: str
    source_version_id: str
    title: str
    text: str
    uri: str
    publisher: str
    published_at: str | None
    retrieved_at: str
    document_sha256: str
    chunk_sha256: str
    chunk_index: int
    chunk_count: int
    start_char: int
    end_char: int
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SearchResult:
    chunk: EvidenceChunk
    score: float

    @property
    def evidence_id(self) -> str:
        return self.chunk.evidence_id

    def to_dict(self) -> dict[str, Any]:
        return {**self.chunk.to_dict(), "relevance_score": round(self.score, 6)}


class EvidenceStore:
    """Local versioned document store with reproducible lexical retrieval.

    Example:
        store = EvidenceStore("data/evidence_store.json")
        store.add_document(
            source_id="tool-policy", title="AI tool authorization policy",
            text="Sensitive actions require independent authorization.",
            uri="https://example.org/tool-policy", publisher="Example Security Team",
        )
        hits = store.search("how are sensitive tool actions authorized", top_k=5)
        context = store.context(hits)  # citation IDs -> evidence text
    """

    def __init__(self, path: str | Path = "data/evidence_store.json") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._documents: list[dict[str, Any]] = []
        self._chunks: list[EvidenceChunk] = []
        if self.path.exists():
            self._load()
        else:
            self._save()
        self._rebuild_index()

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read evidence store {self.path}: {exc}") from exc
        if payload.get("schema_version") != _SCHEMA_VERSION:
            raise ValueError(f"Unsupported evidence store schema: {payload.get('schema_version')!r}")
        documents = payload.get("documents", [])
        chunks = payload.get("chunks", [])
        if not isinstance(documents, list) or not isinstance(chunks, list):
            raise ValueError("Evidence store documents and chunks must be lists")
        self._documents = documents
        try:
            self._chunks = [EvidenceChunk(**row) for row in chunks]
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Evidence store contains an invalid chunk record: {exc}") from exc

    def _save(self) -> None:
        payload = {
            "schema_version": _SCHEMA_VERSION,
            "updated_at": _now_iso(),
            "documents": self._documents,
            "chunks": [chunk.to_dict() for chunk in self._chunks],
        }
        encoded = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as handle:
            handle.write(encoded)
            temporary_path = Path(handle.name)
        temporary_path.replace(self.path)

    def add_document(
        self,
        *,
        source_id: str,
        title: str,
        text: str,
        uri: str = "",
        publisher: str = "",
        published_at: str | None = None,
        retrieved_at: str | None = None,
        metadata: Mapping[str, Any] | None = None,
        chunk_size: int = 900,
        overlap: int = 120,
    ) -> list[EvidenceChunk]:
        """Add a text document and preserve its metadata and content hashes.

        ``uri`` is provenance information only: this method does not fetch the URL or
        authenticate its owner. ``published_at`` is supplied by the caller and is not
        independently verified.
        """
        if not isinstance(source_id, str) or not source_id.strip():
            raise ValueError("source_id must be a non-empty string")
        if not isinstance(title, str) or not title.strip():
            raise ValueError("title must be a non-empty string")
        if not isinstance(text, str) or not text.strip():
            raise ValueError("text must be a non-empty string")
        if chunk_size < 100:
            raise ValueError("chunk_size must be at least 100 characters")
        if overlap < 0 or overlap >= chunk_size:
            raise ValueError("overlap must be >= 0 and smaller than chunk_size")
        metadata_dict = _safe_metadata(metadata)
        content_hash = _sha256(text)
        source_id = source_id.strip()
        source_version_id = f"{source_id}@{content_hash[:12]}"
        now = retrieved_at or _now_iso()
        segments = _make_chunks(text, chunk_size, overlap)
        if not segments:
            raise ValueError("Document did not contain any non-whitespace text")
        document = {
            "source_id": source_id,
            "source_version_id": source_version_id,
            "title": title.strip(),
            "uri": uri.strip(),
            "publisher": publisher.strip(),
            "published_at": published_at,
            "retrieved_at": now,
            "document_sha256": content_hash,
            "content": text,
            "chunk_size": chunk_size,
            "overlap": overlap,
            "metadata": metadata_dict,
        }
        # Keep old content versions; replace exact version to refresh caller-provided metadata.
        self._documents = [doc for doc in self._documents if doc.get("source_version_id") != source_version_id]
        self._documents.append(document)
        self._chunks = [chunk for chunk in self._chunks if chunk.source_version_id != source_version_id]
        total = len(segments)
        added: list[EvidenceChunk] = []
        for index, (chunk_text, start, end) in enumerate(segments):
            evidence_id = "E" + _sha256(f"{source_version_id}:{index}")[:12]
            chunk = EvidenceChunk(
                evidence_id=evidence_id,
                source_id=source_id,
                source_version_id=source_version_id,
                title=title.strip(),
                text=chunk_text,
                uri=uri.strip(),
                publisher=publisher.strip(),
                published_at=published_at,
                retrieved_at=now,
                document_sha256=content_hash,
                chunk_sha256=_sha256(chunk_text),
                chunk_index=index,
                chunk_count=total,
                start_char=start,
                end_char=end,
                metadata=metadata_dict,
            )
            self._chunks.append(chunk)
            added.append(chunk)
        self._save()
        self._rebuild_index()
        return added

    def get(self, evidence_id: str) -> EvidenceChunk | None:
        return next((chunk for chunk in self._chunks if chunk.evidence_id == evidence_id), None)

    def all_chunks(self) -> list[EvidenceChunk]:
        return list(self._chunks)

    def search(self, query: str, *, top_k: int = 5) -> list[SearchResult]:
        """Retrieve passages using BM25-style lexical relevance ranking.

        Scores depend on this corpus and query. They are not probabilities and do not
        establish whether a retrieved passage supports a particular claim.
        """
        if top_k < 1:
            raise ValueError("top_k must be at least 1")
        terms = _tokens(query)
        if not terms or not self._chunks:
            return []
        n_docs = len(self._chunks)
        scores: list[SearchResult] = []
        avg_len = self._avg_doc_length or 1.0
        unique_terms = set(terms)
        k1, b = 1.5, 0.75
        for index, chunk in enumerate(self._chunks):
            token_counts = self._token_counts[index]
            length = sum(token_counts.values())
            score = 0.0
            title_terms = set(_tokens(chunk.title))
            for term in unique_terms:
                frequency = token_counts.get(term, 0)
                if not frequency:
                    continue
                df = self._document_frequency.get(term, 0)
                idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
                denominator = frequency + k1 * (1.0 - b + b * length / avg_len)
                score += idf * (frequency * (k1 + 1.0) / denominator)
                if term in title_terms:
                    score += idf * 0.35
            if score > 0:
                scores.append(SearchResult(chunk, score))
        scores.sort(key=lambda item: (-item.score, item.chunk.source_id, item.chunk.chunk_index))
        return scores[:top_k]

    @staticmethod
    def context(results: Iterable[SearchResult | EvidenceChunk]) -> dict[str, str]:
        """Return the compact citation-ID-to-text mapping accepted by verify_response."""
        context: dict[str, str] = {}
        for result in results:
            chunk = result.chunk if isinstance(result, SearchResult) else result
            context[chunk.evidence_id] = chunk.text
        return context

    @staticmethod
    def prompt_context(results: Iterable[SearchResult]) -> str:
        """Format retrieved snippets with stable citation IDs and provenance metadata.

        This formatting helps a generator cite the evidence it actually received. It does
        not make prompt-injection text inside the source trustworthy; retrieved passages
        must still be treated as untrusted data by the model/application.
        """
        blocks: list[str] = []
        for result in results:
            chunk = result.chunk
            source_line = f"Publisher: {chunk.publisher or 'unknown'}"
            if chunk.published_at:
                source_line += f" | Published: {chunk.published_at}"
            if chunk.uri:
                source_line += f" | URI: {chunk.uri}"
            blocks.append(
                f"[{chunk.evidence_id}] {chunk.title}\n{source_line}\n"
                f"Retrieved: {chunk.retrieved_at} | Document SHA-256: {chunk.document_sha256}\n"
                f"Evidence excerpt (untrusted source data):\n{chunk.text}"
            )
        return "\n\n---\n\n".join(blocks)

    @staticmethod
    def format_sources(results: Iterable[SearchResult]) -> list[dict[str, Any]]:
        """Source cards for UI/report display, including source/chunk hashes."""
        return [
            {
                "evidence_id": result.chunk.evidence_id,
                "title": result.chunk.title,
                "source_id": result.chunk.source_id,
                "uri": result.chunk.uri,
                "publisher": result.chunk.publisher,
                "published_at": result.chunk.published_at,
                "retrieved_at": result.chunk.retrieved_at,
                "relevance_score": round(result.score, 6),
                "document_sha256": result.chunk.document_sha256,
                "chunk_sha256": result.chunk.chunk_sha256,
                "chunk_index": result.chunk.chunk_index,
                "chunk_count": result.chunk.chunk_count,
                "start_char": result.chunk.start_char,
                "end_char": result.chunk.end_char,
            }
            for result in results
        ]

    def _rebuild_index(self) -> None:
        self._token_counts: list[dict[str, int]] = []
        self._document_frequency: dict[str, int] = {}
        total_len = 0
        for chunk in self._chunks:
            tokens = _tokens(chunk.title + " " + chunk.text)
            counts: dict[str, int] = {}
            for token in tokens:
                counts[token] = counts.get(token, 0) + 1
            self._token_counts.append(counts)
            total_len += len(tokens)
            for token in counts:
                self._document_frequency[token] = self._document_frequency.get(token, 0) + 1
        self._avg_doc_length = total_len / len(self._chunks) if self._chunks else 0.0

    def source_manifest(self) -> list[dict[str, Any]]:
        manifest = []
        for doc in self._documents:
            chunks = [chunk for chunk in self._chunks if chunk.source_version_id == doc["source_version_id"]]
            manifest.append({
                "source_id": doc["source_id"],
                "source_version_id": doc["source_version_id"],
                "title": doc["title"],
                "uri": doc["uri"],
                "publisher": doc["publisher"],
                "published_at": doc["published_at"],
                "retrieved_at": doc["retrieved_at"],
                "document_sha256": doc["document_sha256"],
                "chunk_count": len(chunks),
                "metadata": doc["metadata"],
            })
        return manifest

    def verify_integrity(self) -> dict[str, Any]:
        errors: list[dict[str, str]] = []
        docs = {doc.get("source_version_id"): doc for doc in self._documents}
        checked_sources = 0
        checked_chunks = 0
        for version, doc in docs.items():
            checked_sources += 1
            if _sha256(doc.get("content", "")) != doc.get("document_sha256"):
                errors.append({"type": "document_hash_mismatch", "source_version_id": str(version)})
            related = [chunk for chunk in self._chunks if chunk.source_version_id == version]
            if not related:
                errors.append({"type": "missing_chunks", "source_version_id": str(version)})
            for chunk in related:
                checked_chunks += 1
                if _sha256(chunk.text) != chunk.chunk_sha256:
                    errors.append({"type": "chunk_hash_mismatch", "evidence_id": chunk.evidence_id})
                content = doc.get("content", "")
                if content[chunk.start_char:chunk.end_char] != chunk.text:
                    errors.append({"type": "chunk_offset_mismatch", "evidence_id": chunk.evidence_id})
                if chunk.document_sha256 != doc.get("document_sha256"):
                    errors.append({"type": "chunk_document_hash_mismatch", "evidence_id": chunk.evidence_id})
        for chunk in self._chunks:
            if chunk.source_version_id not in docs:
                errors.append({"type": "orphan_chunk", "evidence_id": chunk.evidence_id})
        return {
            "ok": not errors,
            "sources_checked": checked_sources,
            "chunks_checked": checked_chunks,
            "errors": errors,
            "note": "Integrity checks detect accidental or uncoordinated edits; they do not prove that a source is authentic or truthful.",
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage the local EthicsBrain evidence store")
    parser.add_argument("--store", type=Path, default=Path("data/evidence_store.json"))
    subparsers = parser.add_subparsers(dest="command", required=True)
    add = subparsers.add_parser("add", help="ingest a local UTF-8 text or Markdown document")
    add.add_argument("--source-id", required=True)
    add.add_argument("--title", required=True)
    add.add_argument("--file", type=Path, required=True)
    add.add_argument("--uri", default="")
    add.add_argument("--publisher", default="")
    add.add_argument("--published-at", default=None)
    add.add_argument("--chunk-size", type=int, default=900)
    add.add_argument("--overlap", type=int, default=120)
    search = subparsers.add_parser("search", help="retrieve relevant passages")
    search.add_argument("query")
    search.add_argument("--top-k", type=int, default=5)
    subparsers.add_parser("manifest", help="print source provenance records")
    subparsers.add_parser("verify-integrity", help="verify source/chunk hashes and offsets")
    args = parser.parse_args(argv)
    store = EvidenceStore(args.store)
    if args.command == "add":
        text = args.file.read_text(encoding="utf-8")
        chunks = store.add_document(
            source_id=args.source_id, title=args.title, text=text, uri=args.uri,
            publisher=args.publisher, published_at=args.published_at,
            chunk_size=args.chunk_size, overlap=args.overlap,
        )
        print(json.dumps({"added_chunks": len(chunks), "source": store.source_manifest()[-1]}, indent=2, ensure_ascii=False))
    elif args.command == "search":
        print(json.dumps([result.to_dict() | {"relevance_score": round(result.score, 6)} for result in store.search(args.query, top_k=args.top_k)], indent=2, ensure_ascii=False))
    elif args.command == "manifest":
        print(json.dumps(store.source_manifest(), indent=2, ensure_ascii=False))
    elif args.command == "verify-integrity":
        report = store.verify_integrity()
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 2
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
