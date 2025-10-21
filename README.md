# Mijann — Open-Source Semantic Shield for Conversational Agents

> **Elevator**: Mijann is an open-source, LLM-agnostic security shield that inspects, sanitizes, and blocks malicious prompts to prevent jailbreaks, data exfiltration, and unauthorized tool use in conversational agents.

---

## Table of Contents
1. [What is Mijann?](#what-is-mijann)
2. [Key Capabilities](#key-capabilities)
3. [How It Works](#how-it-works)
4. [Install](#install)
5. [Quickstart: Generate Your Shield File](#quickstart-generate-your-shield-file)
6. [Use the Shield With Your LLM](#use-the-shield-with-your-llm)
7. [Configuration Schema](#configuration-schema)
8. [Full Shield Template](#full-shield-template)
9. [Context Window Overhead](#context-window-overhead)
10. [Security Challenge (CTF) Mode](#security-challenge-ctf-mode)
11. [Threat Model and Risk Matrix](#threat-model-and-risk-matrix)
12. [Contributing](#contributing)
13. [License](#license)
14. [Credits and Governance](#credits-and-governance)
15. [FAQ](#faq)

---

## What is Mijann?

Mijann is a defensive semantic shield + lightweight policy that you place **downstream** any conversational agent designed to interact with humans. It detects and neutralizes prompt injection, jailbreaks, secret exfiltration, and tool-abuse without model fine-tuning. It is vendor-neutral and works with OpenAI, Anthropic, Google, open-source LLMs, and inference servers.

---

## Key Capabilities

- **LLM-agnostic**: No training required. Semantic policy + prompt.
- **Ingress detection**: role/priority swap, exfiltration cues, obfuscation blobs, capability escalation.
- **Sanitization**: rewrites or strips untrusted directives while preserving user intent.
- **Tool mediation**: hard allowlist for tools; regenerates safe parameters.
- **Egress filtering**: scans model output for secrets or unsafe payloads.
- **Auditability**: decision rationale tags suitable for logging.

---

## How It Works

A single turn passes three stages:

1. **Ingress**: normalize input; detect jailbreak/injection/obfuscation; compute risk; decide **allow / sanitize / challenge / block**.  
2. **Mid-flight**: enforce the **Mijann system prompt**; restrict tools to the allowlist; minimize parameters.  
3. **Egress**: scan output for **SENSITIVE** matches and unsafe content; redact or refuse if needed.

This design is compositional: the same shield and policy run with any LLM or framework.

---

## Install

Minimal Python utilities are provided for generation and integration.

```bash
git clone https://github.com/KNOWDYN/mijann.git
cd mijann
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Quickstart: Generate Your Shield File 

Mijann ships with an interactive generator that builds your security shield configuration file based on your inputs.

```bash
python tools/mijann_generator.py --interactive --out mijann_security_shield.txt
```

Or pass parameters directly:

```bash
python tools/mijann_generator.py   --title "Semantic Security Shield (LLM-agnostic)"   --capabilities "answer_questions,search_web"   --allow-tools "web.search,calendar.read"   --trusted-contexts "first_party:RAG,calendar"   --sensitive "(AKIA[0-9A-Z]{16}),(sk_(live|prod)_[0-9A-Za-z]{16,})"   --risk-mode MEDIUM   --output-format normal   --out mijann_security_shield.txt
```

---

## Use the Shield With Your LLM

```python
from openai import OpenAI
from pathlib import Path

shield = Path("mijann_security_shield.txt").read_text()

client = OpenAI()
resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": shield},
        {"role": "system", "content": "Your assistant logic here."},
        {"role": "user", "content": "Hello!"}
    ]
)
print(resp.choices[0].message.content)
```

---

## Configuration Schema

```json
{
  "capabilities": ["answer_questions", "search_web"],
  "allow_tools": ["web.search", "calendar.read"],
  "trusted_contexts": ["first_party:RAG", "calendar"],
  "sensitive_patterns": [
    "(AKIA[0-9A-Z]{16})",
    "(sk_(live|prod)_[0-9A-Za-z]{16,})"
  ],
  "risk": { "default": "MEDIUM" },
  "output_format": "normal"
}
```

---

## Full Shield Template

Located in `templates/mijann_shield.txt`. Customize for your environment.

---

## Context Window Overhead

Adds ~900–1,100 tokens (<1% of 128k context).  
Check count with:

```bash
python tools/token_count.py mijann_security_shield.txt
```

---

## Security Challenge (CTF) Mode

Create a challenge by hiding a secret (e.g. `FLAG{X9a7Kp2LmQ4t}`) behind the shield.  
Participants attempt to extract it without triggering alerts.  
Use logs for scoring and hardening analysis.

---

## Threat Model and Risk Matrix

Refer to `WHITEPAPER.md`. It maps STRIDE threats to Mijann controls and shows likelihood-impact mitigation matrices.

---

## Contributing

Submit improvements via PR. Run:

```bash
ruff check .
pytest
```

---

## License

Mijann © 2025 KNOWDYN  
Released under the **Creative Commons Attribution–NonCommercial 4.0 International License (CC BY-NC 4.0)**.

You are free to:
- Share — copy and redistribute the material in any medium or format.
- Adapt — remix, transform, and build upon the material.

Under the following terms:
- **Attribution** — you must give appropriate credit and link to the source repository.
- **NonCommercial** — you may not use the material for commercial purposes.
- **No additional restrictions** — you may not apply legal or technological measures that restrict others from exercising the rights granted here.

See the full license text at: [https://creativecommons.org/licenses/by-nc/4.0/](https://creativecommons.org/licenses/by-nc/4.0/)

---

## Credits and Governance

Developed by **KNOWDYN**.  
Brand name **Mijann** (Arabic **مِجَنّ**, meaning "shield"). Community-driven, transparent security project.

---

## FAQ

**Q1: What does the name “Mijann” mean?**  
“Mijann” (Arabic: **مِجَنّ**) means *shield* or *protective barrier*. It is pronounced *mi-jann*, with stress on the second syllable. In pre-Islamic Arabic poetry, the word described the defensive shield of a warrior—a disciplined guard that deflects attacks while preserving strength and agility. Mijann’s mission mirrors this: to guard conversational agents without restricting their intelligence.

**Q2: How is Mijann different from other prompt security tools?**  
Mijann operates entirely at the **prompt level**, requiring no model fine-tuning or middleware. It is *zero-shot*, meaning its protection logic is encoded in language and formal rules that work with any LLM. Other tools rely on API-specific filters or classifiers; Mijann works across all models as a declarative system prompt.

**Q3: Does Mijann reduce the quality of responses?**  
Minimal. The default `MEDIUM` risk mode is tuned to allow benign requests and block only risky ones. False positives can occur if user input includes obfuscation or unsafe keywords, but the generator allows configuration per deployment.

**Q4: Can Mijann protect against unseen or novel jailbreaks?**  
Partially. Mijann applies logical reasoning and pattern matching to block unknown injection types by policy generalization. However, adversaries may always find bypasses, so periodic updates and red-teaming are advised.

**Q5: How does Mijann detect secret exfiltration?**  
It uses layered pattern matching (regex, entropy heuristics, and contextual tags) to identify probable secrets or internal URLs. If detected, the shield refuses or sanitizes output before transmission.

**Q6: Is Mijann compatible with OpenAI, Anthropic, or Google Gemini APIs?**  
Yes. Mijann is **LLM-agnostic**—its logic is language-level. You can embed its system prompt into any API’s system or developer message field.

**Q7: Can developers extend Mijann?**  
Yes. The Python generator supports modular injection of detection rules, custom regex lists, or additional risk functions. Fork and extend safely under Apache-2.0.

**Q8: How large is the shield text?**  
Typically 900–1,100 tokens, negligible for modern 128k–1M context windows.

**Q9: What if a request seems suspicious but legitimate?**  
Mijann’s *clarification mode* triggers at medium risk: the model asks one focused yes/no question to confirm intent before proceeding. This keeps the system responsive without overblocking.

**Q10: How can I participate in testing or red-teaming?**  
Run the public challenge described in section [10. Security Challenge (CTF) Mode](#10-security-challenge-ctf-mode). You can host a local copy or join community events announced via the GitHub repository.

**Q11: What license governs Mijann?**  
Apache License 2.0 — open for modification, redistribution, and commercial integration with attribution.

**Q12: Who maintains Mijann?**  
Developed by **KNOWDYN**, maintained by the open-source community. Governance is transparent; contributors are credited in `CONTRIBUTORS.md`.

---
## Disclaimer

Mijann is experimental software provided without warranty. It mitigates, but does not eliminate, prompt-injection and data-exfiltration risks. Use at your own discretion and verify configurations independently. The maintainers and contributors assume no responsibility for security incidents, losses, or misuse resulting from its deployment.
