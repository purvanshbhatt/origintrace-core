import sys
import os
import json
from extractors.pe_extractor import extract_local_features
from agents.intelligence import MasterIntelligenceAgent

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_malware_sample.exe>")
        sys.exit(1)

    target_file = sys.argv[1]
    api_key = os.environ.get("GEMINI_API_KEY")
    
    if not api_key:
        print("[!] ERROR: Please set your GEMINI_API_KEY environment variable.")
        sys.exit(1)

    print(f"[*] OriginTrace MVP initialized.")
    print(f"[*] Step 1: Running local deterministic extraction on {target_file}...")
    
    # 1. Run local extraction
    features = extract_local_features(target_file)
    if "error" in features["status"]:
        print(f"[!] Extraction failed: {features['status']}")
        sys.exit(1)
        
    print(f"    [+] Extracted {len(features['imports'])} imports and {len(features['strings'])} high-value strings.")
    
    # 2. Run LLM Analysis
    print("[*] Step 2: Passing context to Gemini 1.5 Pro for Semantic Provenance Analysis...")
    agent = MasterIntelligenceAgent(api_key=api_key)
    
    try:
        report = agent.analyze(features)
        print("\n" + "="*50)
        print("🚀 ORIGINTRACE FINAL INTELLIGENCE REPORT")
        print("="*50)
        print(json.dumps(report, indent=2))
        
        # Optional: Save to file
        with open("origintrace_report.json", "w") as f:
            json.dump(report, f, indent=2)
        print("\n[*] Report saved to origintrace_report.json")
        
    except Exception as e:
        print(f"[!] Analysis failed: {str(e)}")

if __name__ == "__main__":
    main()
