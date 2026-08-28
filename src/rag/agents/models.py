from src.rag.agents.prompts import RAG
from src.llm import fetch_llm

# Call RAG agent
def start_rag(context: str, model: str = None) -> dict:

    prompt = RAG.replace("{context}", context)

    return fetch_llm(prompt, model=model, jfmt=True)