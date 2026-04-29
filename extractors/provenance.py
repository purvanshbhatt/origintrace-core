import os
import json
import faiss
import numpy as np
from datetime import datetime, timezone
from sentence_transformers import SentenceTransformer

# Paths for persistent FAISS index and registry
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
INDEX_PATH = os.path.join(DATA_DIR, "provenance_index.faiss")
REGISTRY_PATH = os.path.join(DATA_DIR, "library_registry.json")
DELTA_CORPUS_PATH = os.path.join(DATA_DIR, "delta_corpus.jsonl")

class ProvenanceEngine:
    def __init__(self):
        """
        Initializes the Semantic Provenance Module using local sentence-transformers 
        and a FAISS CPU index for zero-cost, lightning-fast vector search.
        """
        # 1. Load the local embedding model (runs completely offline/locally)
        # 'all-MiniLM-L6-v2' is small, fast, and generates 384-dimensional vectors
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.dimension = 384

        # 2. Ensure data directory exists
        os.makedirs(DATA_DIR, exist_ok=True)

        # 3. Load persisted index or bootstrap a fresh one
        if os.path.exists(INDEX_PATH) and os.path.exists(REGISTRY_PATH):
            self.index = faiss.read_index(INDEX_PATH)
            with open(REGISTRY_PATH, "r") as f:
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
        mock_baselines = {
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

        for lib_id, lib_data in mock_baselines.items():
            self.library_registry[lib_id] = lib_data
            text_payload = " ".join(lib_data["signatures"])
            embedding = self.model.encode([text_payload])
            faiss.normalize_L2(embedding)
            self.index.add_with_ids(embedding, np.array([lib_id], dtype=np.int64))

    def _persist_index(self):
        """Writes the FAISS index and library registry to disk."""
        faiss.write_index(self.index, INDEX_PATH)
        with open(REGISTRY_PATH, "w") as f:
            json.dump(self.library_registry, f, indent=2)

    def analyze_delta(self, extracted_strings: list[str], extracted_imports: list[str]) -> dict:
        """
        Identifies if an extracted binary matches a known open-source library, 
        and extracts the specific 'Semantic Delta' (malicious, injected logic).
        """
        all_features = extracted_strings + extracted_imports
        if not all_features:
            return {
                "ecosystem_match": "None",
                "legitimate_baseline": [],
                "injected_artifacts": []
            }
            
        combined_payload = " ".join(all_features)

        # 1. Embed the target malware
        target_embedding = self.model.encode([combined_payload])
        faiss.normalize_L2(target_embedding)

        # 2. Search FAISS for the k=1 nearest neighbor
        distances, indices = self.index.search(target_embedding, 1)
        
        score = float(distances[0][0])
        match_id = int(indices[0][0])

        # 3. Match Logic: Determine if it's a hijacked library or native malware
        THRESHOLD = 0.80

        if score >= THRESHOLD and match_id != -1:
            matched_lib = self.library_registry[match_id]
            match_name = matched_lib["name"]
            baseline = matched_lib["signatures"]
            baseline_set = set(baseline)
            injected_artifacts = [item for item in all_features if item not in baseline_set]

            result = {
                "ecosystem_match": f"{match_name} ({score * 100:.0f}% similarity)",
                "legitimate_baseline": baseline,
                "injected_artifacts": injected_artifacts
            }
        else:
            injected_artifacts = all_features
            result = {
                "ecosystem_match": f"Native/Unknown (Best match: {score * 100:.0f}%)",
                "legitimate_baseline": [],
                "injected_artifacts": injected_artifacts
            }

        # 4. Log the semantic delta to the research corpus
        self._log_delta(result, injected_artifacts)

        return result

    def _log_delta(self, provenance_result: dict, injected_artifacts: list[str]):
        """Appends the semantic delta record to a JSONL corpus for research."""
        if provenance_result["ecosystem_match"] == "None":
            return
        delta_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "matched_library": provenance_result["ecosystem_match"],
            "delta_size": len(injected_artifacts),
            "injected_artifacts": injected_artifacts[:20]
        }
        try:
            with open(DELTA_CORPUS_PATH, "a") as f:
                f.write(json.dumps(delta_record) + "\n")
        except Exception:
            pass  # Non-critical; don't crash the pipeline for logging
