# OriginTrace

**Autonomous Semantic Provenance (ASP)**

## The Narrative
OriginTrace is the technical forensic engine under the ResilAI ecosystem. While ResilAI handles high-level risk and governance, OriginTrace is the "hard-hat" tool that identifies malicious code-level discrepancies (deltas) in hijacked libraries.

## The Supply Chain Pivot
Traditional security relies on reactive detection—flagging a threat only after it has executed or matched a known signature. OriginTrace shifts the paradigm from **reactive detection** to **autonomous attribution**. We dissect software supply chain components at a fundamental level, automatically identifying where malicious modifications were introduced, prioritizing the source and lineage of the code block before it deploys.

## Autonomous Semantic Provenance (ASP)
We are defining a new category of cybersecurity: **Autonomous Semantic Provenance (ASP)**.
ASP goes beyond static and dynamic analysis. It understands the *meaning* (semantics) of code changes and autonomously traces the *origin* (provenance) of those changes. By analyzing behavioral features, AST deltas, and cross-referencing global threat intelligence, OriginTrace maps behaviors to MITRE ATT&CK techniques and isolates hijacked elements from native code with unprecedented accuracy.

## Competitive Advantage
OriginTrace is built for the modern threat landscape, offering distinct advantages over traditional tools:

* **vs. Ghidra**: **Speed.** Manual reverse engineering in Ghidra can take days or weeks for a skilled analyst. OriginTrace automates this workflow, delivering deep code analysis and behavioral parsing in a fraction of the time.
* **vs. CAPA**: **Provenance Context.** While CAPA is excellent for identifying capabilities, it lacks historical and contextual awareness. OriginTrace provides the full provenance—not just *what* the code does, but *where* it came from and *how* it was altered.
* **vs. VirusTotal (VT)**: **The "Why".** VT tells you *if* a file is bad based on community consensus and antivirus engines. OriginTrace tells you *why* it's bad, providing the underlying semantic reasoning, the specific malicious deltas, and the precise context needed to write robust detection engineering rules.

## Ecosystem Architecture: OriginTrace vs. ResilAI
To prevent brand confusion, it is critical to understand the distinction between our core offerings:

* **OriginTrace**: The **Technical Engine**. The hard-hat forensic tool for SOC analysts and detection engineers. It performs the deep code-level analysis, binary inspection, and logic tracing.
* **ResilAI**: The **Governance Layer**. The executive dashboard for CISOs and risk managers. It consumes intelligence from OriginTrace to quantify business risk, ensure compliance, and orchestrate automated policy enforcement.

## Brand Guidelines
When building community-contributed rules, custom integrations, or extending the Investigation Workbench, please adhere to our core color palette:

* **Resilience Cyan**: Represents verified, safe provenance, trusted libraries, clean code paths, and optimal system health.
* **Infection Crimson**: Represents malicious deltas, hijacked behaviors, identified threats, and compromised dependencies.
