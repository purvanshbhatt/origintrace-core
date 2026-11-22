"""
OriginTrace — Semantic Provenance Engine

Decides whether a sample's extracted features resemble a known open-source
library and, if so, which artifacts fall outside that library's baseline
(the injected "semantic delta").

Two interchangeable engines share one result shape:

  ProvenanceEngine         sentence-transformers embeddings + FAISS search
                           (production; needs faiss-cpu and a ~90 MB model)
  LexicalProvenanceEngine  signature containment, no dependencies
                           (fallback when the vector stack is unavailable)

`get_provenance_engine()` picks one; set ORIGINTRACE_PROVENANCE to
auto | faiss | lexical | off to force a choice.
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("origintrace.provenance")

# Paths for persistent FAISS index and registry
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
INDEX_PATH = os.path.join(DATA_DIR, "provenance_index.faiss")
REGISTRY_PATH = os.path.join(DATA_DIR, "library_registry.json")
DELTA_CORPUS_PATH = os.path.join(DATA_DIR, "delta_corpus.jsonl")

MAX_ARTIFACTS = 200   # bound the report payload for symbol-heavy binaries

# Embedded signatures of known-good libraries.
BASELINE_LIBRARIES: Dict[int, Dict[str, Any]] = {
    1: {
        "name": "PyPI: requests-v2",
        "signatures": [
            "import urllib3", "requests.get", "requests.post", "Session", "User-Agent: python-requests"
        ]
    },
    2: {
        "name": "PyPI: boto3-v1.2",
        "signatures": [
            "import botocore", "boto3.client('s3')", "aws_access_key_id", "aws_secret_access_key"
        ]
    },
    3: {
        "name": "NPM: express-js",
        "signatures": [
            "const express = require('express')", "app.listen", "app.get", "req, res, next"
        ]
    }
}


def _empty_result(engine: str) -> Dict[str, Any]:
    return {
        "ecosystem_match": "None",
        "legitimate_baseline": [],
        "injected_artifacts": [],
        "engine": engine,
    }


def _matched_result(name: str, score: float, baseline: List[str],
                    all_features: List[str], engine: str) -> Dict[str, Any]:
    baseline_set = set(baseline)
    injected = [item for item in all_features if item not in baseline_set]
    return {
        "ecosystem_match": f"{name} ({score * 100:.0f}% similarity)",
        "legitimate_baseline": baseline,
        "injected_artifacts": injected[:MAX_ARTIFACTS],
        "engine": engine,
    }


def _native_result(score: float, all_features: List[str], engine: str) -> Dict[str, Any]:
    return {
        "ecosystem_match": f"Native/Unknown (Best match: {score * 100:.0f}%)",
        "legitimate_baseline": [],
        "injected_artifacts": all_features[:MAX_ARTIFACTS],
        "engine": engine,
    }


class LexicalProvenanceEngine:
    """
    Dependency-free provenance: a library matches when enough of its known
    signatures literally appear in the sample's features.
    """

    name = "lexical"
    THRESHOLD = 0.6
    MIN_SIGNATURE_HITS = 2

    def __init__(self, baselines: Optional[Dict[int, Dict[str, Any]]] = None):
        self.library_registry = baselines or BASELINE_LIBRARIES

    def analyze_delta(self, extracted_strings: List[str], extracted_imports: List[str]) -> Dict[str, Any]:
        """Match features against library baselines and return the delta."""
        all_features = list(extracted_strings) + list(extracted_imports)
        if not all_features:
            return _empty_result(self.name)

        haystack = "\n".join(all_features).lower()
        best_score, best_hits, best_lib = 0.0, 0, None
        for library in self.library_registry.values():
            signatures = library["signatures"]
            hits = sum(1 for signature in signatures if signature.lower() in haystack)
            score = hits / len(signatures) if signatures else 0.0
            if score > best_score:
                best_score, best_hits, best_lib = score, hits, library

        if best_lib and best_score >= self.THRESHOLD and best_hits >= self.MIN_SIGNATURE_HITS:
            return _matched_result(best_lib["name"], best_score, best_lib["signatures"], all_features, self.name)
        return _native_result(best_score, all_features, self.name)


class ProvenanceEngine:
    """Semantic provenance backed by local embeddings and a FAISS index."""

    name = "faiss-minilm"
    THRESHOLD = 0.80

    def __init__(self):
        """
        Initializes the Semantic Provenance Module using local sentence-transformers
        and a FAISS CPU index for zero-cost, lightning-fast vector search.
        """
        # Heavy dependencies are imported here, not at module import time, so
        # the rest of the pipeline works on machines without them.
        import faiss
        import numpy as np
        from sentence_transformers import SentenceTransformer

        self._faiss = faiss
        self._np = np

        # 1. Load the local embedding model (runs completely offline/locally)
        # 'all-MiniLM-L6-v2' is small, fast, and generates 384-dimensional vectors
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.dimension = 384

        # 2. Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)

        # 3. Load persisted index or bootstrap a fresh one
        if os.path.exists(INDEX_PATH) and os.path.exists(REGISTRY_PATH):
            self.index = faiss.read_index(INDEX_PATH)
            with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
                self.library_registry = json.load(f)
            # Convert string keys back to int (JSON serializes dict keys as strings)
            self.library_registry = {int(k): v for k, v in self.library_registry.items()}
        else:
            self.index = faiss.IndexIDMap(faiss.IndexFlatIP(self.dimension))
            self.library_registry = {}
            self._bootstrap_index()
            self._persist_index()

    def _bootstrap_index(self):
        """
        Bootstraps a FAISS index containing embedded signatures of known-good libraries.
        """
        for lib_id, lib_data in BASELINE_LIBRARIES.items():
            self.library_registry[lib_id] = lib_data
            text_payload = " ".join(lib_data["signatures"])
            embedding = self.model.encode([text_payload])
            self._faiss.normalize_L2(embedding)
            self.index.add_with_ids(embedding, self._np.array([lib_id], dtype=self._np.int64))

    def _persist_index(self):
        """Writes the FAISS index and library registry to disk."""
        self._faiss.write_index(self.index, INDEX_PATH)
        with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(self.library_registry, f, indent=2)

    def analyze_delta(self, extracted_strings: List[str], extracted_imports: List[str]) -> Dict[str, Any]:
        """
        Identifies if an extracted binary matches a known open-source library,
        and extracts the specific 'Semantic Delta' (malicious, injected logic).
        """
        all_features = list(extracted_strings) + list(extracted_imports)
        if not all_features:
            return _empty_result(self.name)

        combined_payload = " ".join(all_features)

        # 1. Embed the target malware
        target_embedding = self.model.encode([combined_payload])
        self._faiss.normalize_L2(target_embedding)

        # 2. Search FAISS for the k=1 nearest neighbor
        distances, indices = self.index.search(target_embedding, 1)

        score = float(distances[0][0])
        match_id = int(indices[0][0])

        # 3. Match Logic: Determine if it's a hijacked library or native malware
        if score >= self.THRESHOLD and match_id in self.library_registry:
            matched_lib = self.library_registry[match_id]
            result = _matched_result(matched_lib["name"], score, matched_lib["signatures"], all_features, self.name)
        else:
            result = _native_result(max(score, 0.0), all_features, self.name)

        # 4. Log the semantic delta to the research corpus
        self._log_delta(result)

        return result

    def _log_delta(self, provenance_result: Dict[str, Any]):
        """Appends the semantic delta record to a JSONL corpus for research."""
        injected_artifacts = provenance_result["injected_artifacts"]
        delta_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "matched_library": provenance_result["ecosystem_match"],
            "delta_size": len(injected_artifacts),
            "injected_artifacts": injected_artifacts[:20]
        }
        try:
            with open(DELTA_CORPUS_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(delta_record) + "\n")
        except OSError as e:
            # Non-critical; don't crash the pipeline for logging
            logger.debug(f"[Provenance] delta corpus write failed: {e}")


def get_provenance_engine(preference: Optional[str] = None) -> Optional[Any]:
    """
    Return the best available provenance engine, or None when disabled.

    preference: auto (default) | faiss | lexical | off. Falls back to the
    ORIGINTRACE_PROVENANCE environment variable.
    """
    choice = (preference or os.environ.get("ORIGINTRACE_PROVENANCE", "auto")).strip().lower()
    if choice == "off":
        return None
    if choice in ("auto", "faiss"):
        try:
            return ProvenanceEngine()
        except Exception as e:
            if choice == "faiss":
                raise
            logger.warning(f"[Provenance] vector engine unavailable ({type(e).__name__}: {e}); using lexical matching")
    return LexicalProvenanceEngine()
