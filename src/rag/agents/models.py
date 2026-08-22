from src.rag.agents.prompts import RAG
from src.llm import fetch_llm

# Hàm Retrieval-Augmented Generation
def start_rag(context: str, model: str = None) -> dict:

    prompt = RAG.replace("{context}", context)

    return fetch_llm(prompt, model=model, jfmt=True)