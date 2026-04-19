# 🔬 OriginTrace

**AI-Powered Malware Provenance & Supply Chain Attribution Engine**

OriginTrace is a lightweight malware analysis tool that combines deterministic local PE extraction with LLM-powered intelligence to produce:
- MITRE ATT&CK technique mapping with evidence
- Semantic Provenance Analysis (supply chain hijack detection)
- Production-grade YARA rules (static detection)
- Sigma rules (behavioral detection)

## Architecture

```
┌─────────────────────┐     ┌──────────────────────────┐
│  PE Extractor       │     │  Master Intelligence     │
│  (Local / Free)     │────▶│  Agent (Gemini 2.0)      │
│                     │     │                          │
│  • SHA256/MD5/ImpH  │     │  • MITRE ATT&CK Mapping  │
│  • API Imports      │     │  • Supply Chain Analysis  │
│  • String Analysis  │     │  • YARA/Sigma Generation  │
└─────────────────────┘     └──────────────────────────┘
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Set API Key
```powershell
# Windows
$env:GEMINI_API_KEY = "your_key_here"
```
```bash
# Linux/Mac
export GEMINI_API_KEY="your_key_here"
```

### 3. Analyze a PE Binary
```bash
python main.py <path_to_sample.exe>
```

### Example Output
```json
{
  "summary": {
    "behavior": "Credential harvesting trojan with C2 callback capability",
    "threat_level": "High"
  },
  "mitre_mapping": [
    {
      "technique_id": "T1003",
      "technique_name": "OS Credential Dumping",
      "evidence": "Imports: advapi32.dll:LsaRetrievePrivateData, crypt32.dll:CryptUnprotectData"
    }
  ],
  "attribution": {
    "origin": "pip",
    "suspected_package": "requests-toolkit"
  },
  "detections": {
    "yara_rule": "rule OriginTrace_CredHarvester { ... }",
    "sigma_rule": "title: Suspicious Credential Access via CryptUnprotectData ..."
  }
}
```

## Project Structure
```
origintrace-core/
├── main.py                    # CLI orchestrator
├── requirements.txt           # Python dependencies
├── extractors/
│   ├── __init__.py
│   └── pe_extractor.py        # Deterministic PE feature extraction
└── agents/
    ├── __init__.py
    └── intelligence.py        # Gemini LLM analysis agent
```

## License

MIT
