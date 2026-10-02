"""HTTP client for the internal API (used by the Streamlit pages)."""

from __future__ import annotations

from typing import Any

import httpx


class ApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status, self.detail = status, detail


class ApiClient:
    def __init__(self, base_url: str, api_key: str, analyst: str, timeout: float = 600.0) -> None:
        self._http = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout)
        self._headers = {"Authorization": f"Bearer {api_key}", "X-Analyst": analyst}

    def _call(self, method: str, path: str, **kw: Any) -> Any:
        resp = self._http.request(method, path, headers=self._headers, **kw)
        if resp.status_code >= 400:
            try:
                detail = resp.json().get("detail", resp.text)
            except ValueError:
                detail = resp.text
            raise ApiError(resp.status_code, str(detail))
        return resp.json()

    def get(self, path: str, **params: Any) -> Any:
        return self._call("GET", path, params={k: v for k, v in params.items() if v is not None})

    def post(self, path: str, json: Any = None, **params: Any) -> Any:
        return self._call("POST", path, json=json, params=params)

    def put(self, path: str, json: Any) -> Any:
        return self._call("PUT", path, json=json)

    def upload(self, data: bytes, **params: Any) -> Any:
        return self._call("POST", "/intelligence/upload", content=data, params=params)
