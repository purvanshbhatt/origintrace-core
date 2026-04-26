import faiss
import numpy as np
from sentence_transformers import SentenceTransformer

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
        
        # 2. Initialize FAISS Index 
        # We use IndexFlatIP (Inner Product) and normalize our vectors so that IP == Cosine Similarity
        # We wrap it in IndexIDMap to assign arbitrary integer IDs to our known good libraries
        self.index = faiss.IndexIDMap(faiss.IndexFlatIP(self.dimension))
        
        # 3. Registry mapping FAISS ID to library names and their baseline signatures
        self.library_registry = {}
        
        # 4. Spin up the initial database state
        self._bootstrap_dummy_index()

    def _bootstrap_dummy_index(self):
        """
        Bootstraps a mock FAISS index containing embedded signatures of known-good libraries.
        (e.g., 'boto3-v1.2', 'requests-v2', 'express-js')
        """
        # Define mock baselines for known libraries
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
        
        # Embed and index each baseline library
        for lib_id, lib_data in mock_baselines.items():
            self.library_registry[lib_id] = lib_data
            
            # We join the signatures into a single "Document" representing the library's typical footprint
            text_payload = " ".join(lib_data["signatures"])
            
            # Embed the text and normalize it for precise Cosine Similarity indexing
            embedding = self.model.encode([text_payload])
            faiss.normalize_L2(embedding)
            
            # Add to the FAISS index with our custom ID
            self.index.add_with_ids(embedding, np.array([lib_id], dtype=np.int64))

    def analyze_delta(self, extracted_strings: list[str], extracted_imports: list[str]) -> dict:
        """
        Identifies if an extracted binary matches a known open-source library, 
        and extracts the specific 'Semantic Delta' (malicious, injected logic).
        """
        # Combine all extracted features into the malware's unified footprint
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
        # Since we use IndexFlatIP and L2 normalized vectors, 'distances' represents Cosine Similarity (0.0 to 1.0)
        distances, indices = self.index.search(target_embedding, 1)
        
        score = float(distances[0][0])
        match_id = int(indices[0][0])

        # 3. Match Logic: Determine if it's a hijacked library or native malware
        THRESHOLD = 0.80 # 80% similarity threshold
        
        if score >= THRESHOLD and match_id != -1:
            matched_lib = self.library_registry[match_id]
            match_name = matched_lib["name"]
            baseline = matched_lib["signatures"]
            
            # 4. Calculate the Delta
            # Any extracted string/import NOT found in the library's legitimate baseline is the "injected artifact"
            baseline_set = set(baseline)
            injected_artifacts = [item for item in all_features if item not in baseline_set]

            return {
                "ecosystem_match": f"{match_name} ({score * 100:.0f}% similarity)",
                "legitimate_baseline": baseline,
                "injected_artifacts": injected_artifacts
            }
        else:
            # If no match >80% is found, assume it is standalone native malware, not a hijacked library
            return {
                "ecosystem_match": f"Native/Unknown (Best match: {score * 100:.0f}%)",
                "legitimate_baseline": [],
                "injected_artifacts": all_features
            }
