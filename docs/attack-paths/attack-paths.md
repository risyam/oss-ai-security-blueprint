# Attack Paths: The Open Source AI Stack

This diagram overlays major attack vectors on the AI system data flow architecture. Each attack category has a **distinct color** for easy identification.

```mermaid
graph TD
    %% Attacker Entry
    Attacker(["⚠ Attacker"])

    %% Nodes
    User([User])

    subgraph Frontend ["Frontend Layer"]
        UI["Web Interface<br/>(Next.js / Streamlit)"]
    end

    subgraph Backend ["Backend & Orchestration"]
        API["API Gateway<br/>(FastAPI)"]
        Orchestrator["Orchestration<br/>(LangChain / LlamaIndex)"]
    end

    subgraph Models ["Model Layer"]
        EmbedModel["Embedding Model<br/>(Nomic / JinaAI)"]
        Inference["Inference Engine<br/>(Ollama / vLLM)"]
        LLM["LLM Weights<br/>(Llama 3 / Mistral / Gemma)"]
    end

    subgraph Data ["Data Layer"]
        VectorDB[("Vector Database<br/>(Milvus / Weaviate / PGVector)")]
        Documents[("Source Documents")]
    end

    %% Normal Data Flow (gray, indices 0-13)
    User -->|Prompt| UI
    UI -->|Request| API
    API -->|Forward| Orchestrator
    Orchestrator -->|Embed| EmbedModel
    EmbedModel -.->|Vector| Orchestrator
    Orchestrator -->|Query| VectorDB
    VectorDB -.->|Context| Orchestrator
    Orchestrator -->|Prompt + Context| Inference
    Inference -.->|Load| LLM
    LLM -.->|Weights| Inference
    Inference -.->|Response| Orchestrator
    Orchestrator -->|Result| API
    API -->|JSON| UI
    UI -->|Display| User

    %% === ATTACK PATHS ===

    %% Path 1: Frontend Attacks (RED - indices 14-15)
    Attacker -.->|"1a. Prompt Injection"| UI
    Attacker -.->|"1b. Jailbreak"| UI

    %% Path 2: API Attacks (ORANGE - indices 16-17)
    Attacker -.->|"2a. Auth Bypass"| API
    Attacker -.->|"2b. Rate Limit Evasion"| API

    %% Path 3: Orchestrator Attacks (YELLOW/GOLD - indices 18-19)
    Attacker -.->|"3a. Chain Poisoning"| Orchestrator
    Attacker -.->|"3b. Tool Abuse"| Orchestrator

    %% Path 4: Vector DB Attacks (GREEN - indices 20-22)
    Attacker -.->|"4a. Vector Poisoning"| Documents
    Documents -.->|"4b. Poisoned Data"| VectorDB
    VectorDB -.->|"4c. Cross-Tenant Leak"| Orchestrator

    %% Path 5: Model Layer Attacks (BLUE - indices 23-24)
    Attacker -.->|"5a. Supply Chain Attack"| LLM
    Inference -.->|"5b. Model Extraction"| Attacker

    %% Path 6: End-to-End Attacks (PURPLE - indices 25-26)
    VectorDB -.->|"6a. Indirect Injection"| Orchestrator
    Orchestrator -.->|"6b. Data Exfiltration"| User


    %% Node Styling
    classDef default fill:#fff,stroke:#333,stroke-width:1px,color:#000;
    classDef userNode fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000;
    classDef attackerNode fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#c62828;
    classDef dbNode fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000;
    classDef modelNode fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000;

    class User userNode;
    class Attacker attackerNode;
    class VectorDB,Documents dbNode;
    class LLM,Inference,EmbedModel modelNode;

    %% Link Styles by Attack Category
    %% Path 1: Frontend (RED)
    linkStyle 14,15 stroke:#c62828,stroke-width:2px,stroke-dasharray:5;
    %% Path 2: API (ORANGE)
    linkStyle 16,17 stroke:#e65100,stroke-width:2px,stroke-dasharray:5;
    %% Path 3: Orchestrator (GOLD)
    linkStyle 18,19 stroke:#f9a825,stroke-width:2px,stroke-dasharray:5;
    %% Path 4: Vector DB (GREEN)
    linkStyle 20,21,22 stroke:#2e7d32,stroke-width:2px,stroke-dasharray:5;
    %% Path 5: Model (BLUE)
    linkStyle 23,24 stroke:#1565c0,stroke-width:2px,stroke-dasharray:5;
    %% Path 6: End-to-End (PURPLE)
    linkStyle 25,26 stroke:#7b1fa2,stroke-width:2px,stroke-dasharray:5;
```

---

## Legend

| Color | Category | Attack Vectors |
|:-----:|----------|----------------|
| 🔴 **Red** | 1. Frontend Attack | Prompt Injection, Jailbreak |
| 🟠 **Orange** | 2. API Attack | Auth Bypass, Rate Limit Evasion |
| 🟡 **Gold** | 3. Orchestrator Attack | Chain Poisoning, Tool Abuse |
| 🟢 **Green** | 4. Vector DB Attack | Vector Poisoning, Cross-Tenant Leak |
| 🔵 **Blue** | 5. Model Layer Attack | Supply Chain, Model Extraction |
| 🟣 **Purple** | 6. End-to-End Attack | Indirect Injection (RAG), Data Exfiltration |

---

## Attack Path Details

| # | Path | Entry Point | Impact | Mitigation |
|---|------|-------------|--------|------------|
| 1a | Prompt Injection | User input | Bypass safety filters, extract data | Input validation, output filtering, system prompt hardening |
| 1b | Jailbreak | User input | Override system instructions | Guardrails (Llama Guard), content moderation, prompt shields |
| 2a | Auth Bypass | API Gateway | Unauthorized access | OAuth 2.0/OIDC, API key rotation, zero-trust architecture |
| 2b | Rate Limit Evasion | API Gateway | DoS, resource exhaustion | Adaptive rate limiting, CAPTCHA, request throttling |
| 3a | Chain Poisoning | Orchestrator | Corrupt reasoning chain | Chain validation, step-by-step verification, sandboxing |
| 3b | Tool Abuse | Orchestrator | Execute unintended tools | Tool allowlisting, permission scoping, human-in-the-loop |
| 4a | Vector Poisoning | Documents | Inject malicious content | Document provenance, content signing, ingestion validation |
| 4b | Poisoned Data | Vector DB | Serve corrupted context | Anomaly detection, embedding integrity checks |
| 4c | Cross-Tenant Leak | Vector DB | Access other users' data | Tenant isolation, namespace separation, RBAC |
| 5a | Supply Chain Attack | LLM Weights | Backdoored model behavior | Model checksums, signed weights, trusted registries |
| 5b | Model Extraction | Inference | Steal model via queries | Query rate limiting, output perturbation, watermarking |
| 6a | Indirect Injection | RAG Context | Hidden instructions in docs | Context sanitization, instruction hierarchy, grounding |
| 6b | Data Exfiltration | Response | Leak sensitive data to user | Output filtering, PII detection, response auditing |
