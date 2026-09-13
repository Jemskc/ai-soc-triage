"""Local HuggingFace LLM backend for the SOC Triage platform.

Config via .env:
  LOCAL_MODEL_NAME    = Qwen/Qwen3-4B   (default)
  LOCAL_MAX_NEW_TOKENS= 1024
"""

from __future__ import annotations

import gc
import json
import os
import re
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_LOCAL_MODEL = "Qwen/Qwen3-4B"


# ─────────────────────────────────────────────────────────────
# JSON helpers
# ─────────────────────────────────────────────────────────────

def _safe_json_parse(text: str) -> dict[str, Any] | None:
    """Parse JSON from LLM output, tolerating markdown fences and reasoning blocks."""
    if not text:
        return None

    cleaned = text.strip()

    # Strip <think>...</think> blocks (Qwen3, DeepSeek-R1).
    stripped = re.sub(r"<think>.*?</think>", "", cleaned, flags=re.DOTALL).strip()
    if stripped and "{" in stripped:
        cleaned = stripped

    # Strip markdown fences.
    if cleaned.startswith("```"):
        match = re.search(r"```(?:json)?\s*(.*?)```", cleaned, re.IGNORECASE | re.DOTALL)
        if match:
            cleaned = match.group(1).strip()

    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass

    # Find first { and try from there.
    idx = cleaned.find("{")
    if idx != -1:
        try:
            obj, _ = json.JSONDecoder().raw_decode(cleaned[idx:])
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass

    return None


# ─────────────────────────────────────────────────────────────
# Base interface
# ─────────────────────────────────────────────────────────────

class LLMBackend:
    def generate_text(
        self,
        system: str,
        user: str,
        max_tokens: int = 800,
        history: list[dict[str, str]] | None = None,
    ) -> str:
        raise NotImplementedError

    def generate_json(
        self,
        system: str,
        user: str,
        max_tokens: int = 700,
    ) -> dict[str, Any] | None:
        text = self.generate_text(system, user, max_tokens=max_tokens)
        return _safe_json_parse(text)

    @property
    def model_label(self) -> str:
        return "unknown"


# ─────────────────────────────────────────────────────────────
# Local HuggingFace backend
# ─────────────────────────────────────────────────────────────

class LocalHFBackend(LLMBackend):
    """Local HuggingFace model backend (Qwen, Llama, Gemma, Mistral…).

    Model is loaded lazily on first call to avoid dashboard startup delay.
    """

    def __init__(self, model_name: str, max_new_tokens: int = 768) -> None:
        self._model_name = model_name
        self._max_new_tokens = max_new_tokens
        self._model = None
        self._tokenizer = None
        self._loaded = False

    def _model_family(self) -> str:
        name = self._model_name.lower()
        if "gemma"    in name: return "gemma"
        if "qwen3"    in name: return "qwen3"   # must come before "qwen"
        if "qwen"     in name: return "qwen"
        if "deepseek" in name: return "deepseek"
        if "mistral"  in name: return "mistral"
        if "llama"    in name: return "llama"
        return "other"

    def _prefers_folded_system(self) -> bool:
        """Gemma rejects a system role — fold it into the user turn."""
        return self._model_family() == "gemma"

    @staticmethod
    def _select_dtype():
        """Pick the fastest dtype the GPU natively supports.

        torch.cuda.is_bf16_supported() reports True on Volta because newer torch
        counts *emulated* bf16. Measured on a V100-PCIE-32GB (SM 7.0), emulated
        bf16 runs at 9.5 TFLOP/s against 84.7 for fp16 — an 8.9x penalty. Gate on
        compute capability instead: native bf16 starts at SM 8.0 (Ampere).
        """
        import torch

        if not torch.cuda.is_available():
            return torch.float32
        major, _ = torch.cuda.get_device_capability()
        return torch.bfloat16 if major >= 8 else torch.float16

    def _load(self) -> None:
        if self._loaded:
            return
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        dtype = self._select_dtype()
        print(f"[+] Loading model: {self._model_name} (dtype={dtype})")
        self._tokenizer = AutoTokenizer.from_pretrained(
            self._model_name, trust_remote_code=True
        )
        self._model = AutoModelForCausalLM.from_pretrained(
            self._model_name,
            dtype=dtype,
            device_map="auto" if torch.cuda.is_available() else None,
            trust_remote_code=True,
        )
        if not torch.cuda.is_available():
            self._model = self._model.to("cpu")
        self._model.eval()
        self._loaded = True
        if torch.cuda.is_available():
            gpu_name = torch.cuda.get_device_name(0)
            mem_gb = torch.cuda.get_device_properties(0).total_memory / 1024**3
            print(f"[+] Model ready on GPU: {gpu_name} ({mem_gb:.1f} GB)")
        else:
            print("[+] Model ready on CPU (no CUDA available)")

    def _build_input(self, system: str, user: str, history: list[dict[str, str]] | None) -> str:
        if self._prefers_folded_system():
            combined_user = f"{system}\n\n{user}" if system else user
            messages = list(history or []) + [{"role": "user", "content": combined_user}]
        else:
            messages = [{"role": "system", "content": system}]
            messages.extend(history or [])
            messages.append({"role": "user", "content": user})

        is_qwen3 = self._model_family() == "qwen3"

        try:
            if is_qwen3:
                # Disable thinking mode so the full token budget goes to the answer.
                # enable_thinking= requires transformers >= 4.51; fall back to /no_think directive.
                try:
                    return self._tokenizer.apply_chat_template(
                        messages,
                        tokenize=False,
                        add_generation_prompt=True,
                        enable_thinking=False,
                    )
                except TypeError:
                    messages[-1]["content"] = messages[-1]["content"].rstrip() + "\n/no_think"
                    return self._tokenizer.apply_chat_template(
                        messages, tokenize=False, add_generation_prompt=True
                    )

            return self._tokenizer.apply_chat_template(
                messages, tokenize=False, add_generation_prompt=True
            )
        except Exception as exc:
            exc_str = str(exc).lower()
            if any(kw in exc_str for kw in ("system role", "conversation roles", "unsupported role", "roles must alternate")):
                combined = (system + "\n\n" if system else "") + user
                return self._tokenizer.apply_chat_template(
                    [{"role": "user", "content": combined}],
                    tokenize=False,
                    add_generation_prompt=True,
                )
            raise

    def generate_text(
        self,
        system: str,
        user: str,
        max_tokens: int = 800,
        history: list[dict[str, str]] | None = None,
    ) -> str:
        import torch

        self._load()

        text_input = self._build_input(system, user, history)
        inputs = self._tokenizer(text_input, return_tensors="pt").to(self._model.device)

        gen_kwargs: dict[str, Any] = {
            "max_new_tokens": min(max_tokens, self._max_new_tokens),
            "do_sample": False,
            "pad_token_id": self._tokenizer.eos_token_id,
        }

        with torch.inference_mode():
            output_ids = self._model.generate(**inputs, **gen_kwargs)

        new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
        response = self._tokenizer.decode(new_tokens, skip_special_tokens=True)

        # Strip <think>...</think> reasoning blocks (Qwen3, DeepSeek-R1).
        stripped = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()
        return stripped if stripped else response

    def generate_batch(
        self,
        prompts: list[tuple[str, str]],
        max_tokens: int = 320,
        batch_size: int = 8,
    ) -> list[str]:
        """Generate for many (system, user) pairs at once.

        One-at-a-time generation leaves the GPU mostly idle: a short JSON
        verdict decodes a few dozen tokens, and the fixed cost of a forward
        pass dominates. Batching amortises that across prompts and turns a
        seven-hour sweep into something that finishes in an evening.

        Decoder-only models must be LEFT-padded for batched generation. With
        right padding the pad tokens sit between the prompt and the first
        generated token, and the model continues from padding rather than from
        the prompt — it produces fluent nonsense, which is far worse than an
        error because it looks like a real answer.
        """
        import torch

        self._load()
        tok = self._tokenizer
        previous_side = tok.padding_side
        if tok.pad_token_id is None:
            tok.pad_token = tok.eos_token
        tok.padding_side = "left"

        out: list[str] = []
        try:
            for start in range(0, len(prompts), batch_size):
                chunk = prompts[start:start + batch_size]
                texts = [self._build_input(sys_, usr, None) for sys_, usr in chunk]
                enc = tok(texts, return_tensors="pt", padding=True).to(
                    self._model.device)

                with torch.inference_mode():
                    ids = self._model.generate(
                        **enc,
                        max_new_tokens=min(max_tokens, self._max_new_tokens),
                        do_sample=False,
                        pad_token_id=tok.pad_token_id,
                    )

                width = enc["input_ids"].shape[1]
                for row in ids:
                    text = tok.decode(row[width:], skip_special_tokens=True)
                    cleaned = re.sub(r"<think>.*?</think>", "", text,
                                     flags=re.DOTALL).strip()
                    out.append(cleaned if cleaned else text)
        finally:
            tok.padding_side = previous_side
        return out

    def generate_stream(
        self,
        system: str,
        user: str,
        max_tokens: int = 800,
        history: list[dict[str, str]] | None = None,
    ):
        """Yield decoded text tokens as they are generated (for streaming responses)."""
        import torch
        from threading import Thread
        from transformers import TextIteratorStreamer

        self._load()

        text_input = self._build_input(system, user, history)
        inputs = self._tokenizer(text_input, return_tensors="pt").to(self._model.device)

        streamer = TextIteratorStreamer(
            self._tokenizer,
            skip_prompt=True,
            skip_special_tokens=True,
            timeout=60.0,
        )

        gen_kwargs: dict[str, Any] = {
            **inputs,
            "max_new_tokens": min(max_tokens, self._max_new_tokens),
            "do_sample": False,
            "pad_token_id": self._tokenizer.eos_token_id,
            "streamer": streamer,
        }

        def _run() -> None:
            with torch.inference_mode():
                self._model.generate(**gen_kwargs)

        thread = Thread(target=_run, daemon=True)
        thread.start()

        # State machine: suppress <think>...</think> blocks on the fly.
        buffer = ""
        in_think = False

        for token in streamer:
            buffer += token
            while True:
                if in_think:
                    end = buffer.find("</think>")
                    if end != -1:
                        buffer = buffer[end + len("</think>"):]
                        in_think = False
                    else:
                        buffer = ""
                        break
                else:
                    start = buffer.find("<think>")
                    if start != -1:
                        if start > 0:
                            yield buffer[:start]
                        buffer = buffer[start + len("<think>"):]
                        in_think = True
                    else:
                        # Keep last 7 chars buffered in case "<think>" is split across tokens.
                        safe = max(0, len(buffer) - 7)
                        if safe > 0:
                            yield buffer[:safe]
                            buffer = buffer[safe:]
                        break

        if buffer and not in_think:
            yield buffer

        thread.join()

    def unload(self) -> None:
        """Release GPU/CPU memory."""
        self._loaded = False
        if self._model is not None:
            del self._model
            self._model = None
        if self._tokenizer is not None:
            del self._tokenizer
            self._tokenizer = None
        gc.collect()
        try:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()
        except ImportError:
            pass

    @property
    def model_label(self) -> str:
        return self._model_name


# ─────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────

_BACKEND_CACHE: LocalHFBackend | None = None


def get_llm_backend(force_reload: bool = False) -> LocalHFBackend | None:
    """Return the local HuggingFace backend, building it once and caching it.

    Reads from .env:
      LOCAL_MODEL_NAME     = Qwen/Qwen3-4B
      LOCAL_MAX_NEW_TOKENS = 1024

    Returns None if LOCAL_MODEL_NAME is not set.
    """
    global _BACKEND_CACHE

    load_dotenv(BASE_DIR / ".env")

    if _BACKEND_CACHE is not None and not force_reload:
        return _BACKEND_CACHE

    model_name = os.getenv("LOCAL_MODEL_NAME", DEFAULT_LOCAL_MODEL).strip()
    max_new_tokens = int(os.getenv("LOCAL_MAX_NEW_TOKENS", "1024"))

    print(f"[+] LLM backend: local ({model_name})")
    _BACKEND_CACHE = LocalHFBackend(model_name=model_name, max_new_tokens=max_new_tokens)
    return _BACKEND_CACHE


def reset_backend_cache() -> None:
    """Force the next get_llm_backend() call to rebuild the backend."""
    global _BACKEND_CACHE
    _BACKEND_CACHE = None
