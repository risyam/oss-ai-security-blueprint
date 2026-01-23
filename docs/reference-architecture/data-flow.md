# Data Flow Diagram: The Open Source AI Stack

Based on the architecture concepts of "The Open Source AI Stack", here is a data flow diagram representing the interaction between the User, Frontend, Backend, Data, and Model layers.

```mermaid
graph TD
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
        LLM["LLM Service<br/>(Ollama / Hugging Face / vLLM)"]
    end
    
    subgraph Data ["Data Layer"]
        VectorDB[("Vector Database<br/>(Milvus / Weaviate / PGVector)")]
    end

    %% Data Flow
    User -->|1. Input Prompt| UI
    UI -->|2. Send Request| API
    API -->|3. Forward| Orchestrator
    
    Orchestrator -->|4. Generate Embeddings| EmbedModel
    EmbedModel -.->|Vector| Orchestrator
    
    Orchestrator -->|5. Query Context| VectorDB
    VectorDB -.->|Relevant Chunks| Orchestrator
    
    Orchestrator -->|6. Prompt + Context| LLM
    LLM -.->|Generated Response| Orchestrator
    
    Orchestrator -->|7. Processed Response| API
    API -->|8. JSON Response| UI
    UI -->|9. Display Result| User

    %% Styling
    classDef plain fill:#fff,stroke:#333,stroke-width:1px,color:#000;
    classDef highlight fill:#e1f5fe,stroke:#01579b,stroke-width:2px,color:#000;
    classDef database fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#000;
    
    class UI,API,Orchestrator,EmbedModel,LLM plain;
    class VectorDB database;
    class User highlight;
```
