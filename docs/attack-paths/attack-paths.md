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
        Registry["Model Registry"]
    end

    subgraph Data ["Data Layer"]
        VectorDB[("Vector Database<br/>(Milvus / Weaviate / PGVector)")]
        Documents[("Source Documents")]
    end

    %% ========================
    %% Normal Data Flow
    %% ========================
    User -->|Prompt| UI
    UI -->|Request| API
    API -->|Forward| Orchestrator
    Orchestrator -->|Embed| EmbedModel
    EmbedModel -.->|Vector| Orchestrator
    Orchestrator -->|Query| VectorDB
    VectorDB -.->|Context| Orchestrator
    Orchestrator -->|Prompt + Context| Inference
    Inference -.->|Load| LLM
    Registry -.->|Pull Weights| LLM
    LLM -.->|Weights| Inference
    Inference -.->|Response| Orchestrator
    Orchestrator -->|Result| API
    API -->|JSON| UI
    UI -->|Display| User

    %% ========================
    %% ATTACK PATHS
    %% ========================

    %% Path 1: Frontend (RED)
    Attacker -.->|"1a. Prompt Injection"| UI
    Attacker -.->|"1b. Jailbreak"| UI

    %% Path 2: API (ORANGE)
    Attacker -.->|"2a. Auth Bypass"| API
    Attacker -.->|"2b. Rate Limit Evasion"| API

    %% Path 3: Orchestrator (GOLD)
    Attacker -.->|"3a. Chain Poisoning"| Orchestrator
    Attacker -.->|"3b. Tool Abuse"| Orchestrator
    Orchestrator -.->|"3c. Secret Exfiltration"| Attacker

    %% Path 4: Vector DB (GREEN)
    Attacker -.->|"4a. Vector Poisoning"| Documents
    Documents -.->|"4b. Poisoned Data"| VectorDB
    VectorDB -.->|"4c. Cross-Tenant Leak"| Orchestrator

    %% Path 5: Model Layer (BLUE)
    Attacker -.->|"5a. Supply Chain Attack"| Registry
    Attacker -.->|"5b. Direct Model Query"| Inference
    Inference -.->|"5c. Model Extraction"| Attacker
    Attacker -.->|"5d. Embedding Manipulation"| EmbedModel

    %% Path 6: End-to-End (PURPLE)
    VectorDB -.->|"6a. Indirect Injection (RAG)"| Orchestrator
    Orchestrator -.->|"6b. Data Exfiltration"| User


    %% ========================
    %% Node Styling
    %% ========================
    classDef default fill:#fff,stroke:#333,stroke-width:1px,color:#000;
    classDef userNode fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#000;
    classDef attackerNode fill:#ffebee,stroke:#c62828,stroke-width:3px,color:#c62828;
    classDef dbNode fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000;
    classDef modelNode fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000;

    class User userNode;
    class Attacker attackerNode;
    class VectorDB,Documents dbNode;
    class LLM,Inference,EmbedModel,Registry modelNode;

    %% ========================
    %% Link Styling by Category
    %% ========================

    %% Frontend (RED)
    linkStyle 15,16 stroke:#c62828,stroke-width:2px,stroke-dasharray:5;

    %% API (ORANGE)
    linkStyle 17,18 stroke:#e65100,stroke-width:2px,stroke-dasharray:5;

    %% Orchestrator (GOLD)
    linkStyle 19,20,21 stroke:#f9a825,stroke-width:2px,stroke-dasharray:5;

    %% Vector DB (GREEN)
    linkStyle 22,23,24 stroke:#2e7d32,stroke-width:2px,stroke-dasharray:5;

    %% Model (BLUE)
    linkStyle 25,26,27,28 stroke:#1565c0,stroke-width:2px,stroke-dasharray:5;

    %% End-to-End (PURPLE)
    linkStyle 29,30 stroke:#7b1fa2,stroke-width:2px,stroke-dasharray:5;


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

| #  | Path                   | Entry Point        | Impact                        | Mitigation                                 |
| -- | ---------------------- | ------------------ | ----------------------------- | ------------------------------------------ |
| 1a | Prompt Injection       | User → UI          | Override system instructions  | Prompt isolation, system message hardening |
| 1b | Jailbreak              | User → UI          | Disable safety layers         | Guard models, layered moderation           |
| 2a | Auth Bypass            | API                | Unauthorized API usage        | OAuth2/OIDC, mTLS                          |
| 2b | Rate Limit Evasion     | API                | DoS / cost explosion          | Adaptive rate limiting                     |
| 3a | Chain Poisoning        | Orchestrator       | Corrupt reasoning chain       | Step verification, execution sandbox       |
| 3b | Tool Abuse             | Orchestrator       | Lateral system compromise     | Tool allowlist, scoped credentials         |
| 3c | Secret Exfiltration    | Tool execution     | Leak tokens / secrets         | Vault-based secret isolation               |
| 4a | Vector Poisoning       | Document ingestion | Malicious context injection   | Content signing, ingestion validation      |
| 4b | Poisoned Retrieval     | Vector DB          | Context corruption            | Retrieval anomaly detection                |
| 4c | Cross-Tenant Leak      | Vector DB          | Data exposure                 | Namespace isolation, RBAC                  |
| 5a | Model Supply Chain     | Registry           | Backdoored weights deployed   | Signed artifacts, checksum validation      |
| 5b | Direct Model Query     | Inference          | Bypass orchestration controls | Network segmentation                       |
| 5c | Model Extraction       | Inference          | Intellectual property theft   | Query monitoring, watermarking             |
| 5d | Embedding Manipulation | Embedding model    | Skew retrieval behavior       | Model integrity checks                     |
| 6a | Indirect Injection     | RAG context        | Hidden instruction execution  | Context sanitization                       |
| 6b | Data Exfiltration      | Response channel   | Sensitive data leakage        | Output filtering, PII scanning             |

