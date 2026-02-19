from __future__ import annotations
import json
import os
import logging
from typing import Any, Dict, List
import httpx
from dotenv import load_dotenv

try:
    from src.extract_schema import DEFAULT_SYSTEM_PROMPT, EXTRACTION_SCHEMA_DESCRIPTION
    from src.pii_masker import PIIMasker
except ImportError:
    from extract_schema import DEFAULT_SYSTEM_PROMPT, EXTRACTION_SCHEMA_DESCRIPTION
    from pii_masker import PIIMasker

load_dotenv()
logger = logging.getLogger(__name__)

class LocalLLMCriticalError(Exception):
    """Raised when Local LLM fails or fallback to Cloud is attempted in Strict Mode."""
    pass

class LLMClient:
    def __init__(self) -> None:
        # 讀取 Provider 設定: openai, azure, 或 local
        self.provider = os.getenv("LLM_PROVIDER", "openai").lower()
        self.timeout = float(os.getenv("OPENAI_TIMEOUT", "60"))
        self.masker = PIIMasker()

        # 根據不同 Provider 初始化設定
        if self.provider == "azure":
            self.api_key = os.getenv("AZURE_OPENAI_KEY")
            endpoint = os.getenv("AZURE_OPENAI_ENDPOINT", "").strip().rstrip("/")
            # 自動補上 https
            if endpoint and not endpoint.startswith("http"):
                endpoint = f"https://{endpoint}"
            self.endpoint = endpoint
            
            self.deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
            self.api_version = os.getenv("AZURE_OPENAI_API_VERSION", "2024-02-15-preview")
            self.model = self.deployment
            self.embedding_deployment = os.getenv("AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME")
        
        elif self.provider == "local":
            self.api_key = "not-needed"
            base = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/v1").strip().rstrip("/")
            if not base.startswith("http"):
                base = f"http://{base}"
            self.base_url = base
            
            self.model = os.getenv("LOCAL_LLM_MODEL", "llama3")
            self.embedding_model = os.getenv("LOCAL_LLM_EMBEDDING_MODEL", "all-minilm")
            
        else: # Default: openai
            self.api_key = os.getenv("OPENAI_API_KEY")
            
            # 網址防呆處理
            base = os.getenv("OPENAI_BASE_URL", "").strip()
            
            # 如果是空字串，強制使用官方預設值
            if not base:
                base = "https://api.openai.com/v1"
            
            # 如果忘記寫 https://，自動補上
            elif not base.startswith("http"):
                base = f"https://{base}"
            
            self.base_url = base.rstrip("/")
            self.model = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
            self.embedding_model = os.getenv("OPENAI_EMBEDDING_MODEL", "text-embedding-3-small")

    def _get_api_config(self, api_type: str = "chat"):
        """ 根據 Provider 動態產出 URL 和 Headers"""
        headers = {"Content-Type": "application/json"}
        
        if self.provider == "azure":
            headers["api-key"] = self.api_key
            deployment = self.deployment if api_type == "chat" else self.embedding_deployment
            url = f"{self.endpoint}/openai/deployments/{deployment}/{'chat/completions' if api_type == 'chat' else 'embeddings'}?api-version={self.api_version}"
        elif self.provider == "local":
            # Local Mock LLM requires no auth headers
            url = f"{self.base_url}/{'chat/completions' if api_type == 'chat' else 'embeddings'}"
        else:
            headers["Authorization"] = f"Bearer {self.api_key}"
            # 這裡的 base_url 已經在 __init__ 被清洗過
            url = f"{self.base_url}/{'chat/completions' if api_type == 'chat' else 'embeddings'}"
            
        return url, headers

    def normalize_log(self, raw_log_text: str) -> dict:
        """ AI 兜底解析 """
        system_prompt = """
        You are an expert Cybersecurity Log Parser. Convert raw log into structured JSON.
        Fields: 'timestamp', 'source_ip', 'destination_ip', 'user', 'action', 'message', 'severity'.
        Output ONLY valid JSON.
        """
        user_prompt = f"Raw Log:\n{raw_log_text}"

        # is_json=True 確保回傳字典
        result = self._call_openai_chat(system_prompt, user_prompt, is_json=True)
        
        if not result or not isinstance(result, dict):
            return {"message": raw_log_text, "parsing_error": "LLM returned invalid format"}
        return result

    def get_embedding(self, text: str) -> List[float]:
        """產生向量 (Embedding)"""
        url, headers = self._get_api_config("embeddings")
        payload = {"input": text.replace("\n", " ")[:8000]}
        if self.provider != "azure":
            payload["model"] = self.embedding_model

        try:
            with httpx.Client(timeout=self.timeout, verify=False) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                return response.json()["data"][0]["embedding"]
        except Exception as e:
            logger.error(f"  [{self.provider}] Embedding failed: {e}")
            return [0.0] * 1536

    def get_extraction(self, text_chunk: str) -> Dict[str, Any]:
        """分析 CTI 報告內容"""
        safe_text = self.masker.mask(text_chunk)
        system_prompt = f"{DEFAULT_SYSTEM_PROMPT}\nOutput Schema:\n{EXTRACTION_SCHEMA_DESCRIPTION}"
        return self._call_openai_chat(system_prompt, safe_text, is_json=True)

    def _call_openai_chat(self, system_prompt: str, user_prompt: str, is_json: bool = False) -> Any:
        """統一的請求發送器 (支援多平台與 JSON 安全解析)"""
        url, headers = self._get_api_config("chat")
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.1
        }
        
        if is_json and self.provider != "local":
            payload["response_format"] = {"type": "json_object"}

        # PRIVACY ENFORCEMENT
        if self.provider == "local":
            if "api.openai.com" in url or "azure.com" in url:
                raise LocalLLMCriticalError("❌ PRIVACY SHIELD: Blocked unauthorized attempt to contact Cloud API in Local Mode (Strict Data Governance).")


        try:
            with httpx.Client(timeout=self.timeout, verify=False) as client:
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                content = response.json()["choices"][0]["message"]["content"]
                
                if is_json:
                    # 針對地端模型過濾 Markdown 標籤
                    clean_content = content.strip().replace("```json", "").replace("```", "").strip()
                    try:
                        return json.loads(clean_content)
                    except json.JSONDecodeError:
                        logger.error(f"  [{self.provider}] LLM returned invalid JSON: {content[:100]}...")
                        return {}
                return content
        except Exception as e:
            if self.provider == "local":
                # Escalate to Critical Error for DLQ Routing
                raise LocalLLMCriticalError(f"Local LLM Unreachable: {e}")
            
            logger.error(f"  [{self.provider}] LLM Request Failed: {e} (URL: {url})")
            return {} if is_json else ""