# app/token_manager.py
import os
import json
import threading
import time
import logging
import requests
from cachetools import TTLCache
from datetime import timedelta

logger = logging.getLogger(__name__)

AUTH_URL = os.getenv("AUTH_URL", "https://jwtxthug.up.railway.app/token")
CACHE_DURATION = timedelta(hours=7).seconds
TOKEN_REFRESH_THRESHOLD = timedelta(hours=6).seconds


class TokenCache:
    def __init__(self, servers_config):
        self.cache = TTLCache(maxsize=100, ttl=CACHE_DURATION)
        self.last_refresh = {}
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.servers_config = servers_config

    def get_tokens(self, server_key):
        with self.lock:
            now = time.time()
            refresh_needed = (
                server_key not in self.cache
                or server_key not in self.last_refresh
                or (now - self.last_refresh.get(server_key, 0)) > TOKEN_REFRESH_THRESHOLD
            )

            if refresh_needed:
                self._refresh_tokens(server_key)
                self.last_refresh[server_key] = now

            return self.cache.get(server_key, [])

    def _refresh_tokens(self, server_key):
        try:
            creds = self._load_credentials(server_key)
            tokens = []

            if not creds:
                logger.warning(f"No credentials found for server {server_key}")
                self.cache[server_key] = []
                return

            for user in creds:
                uid = user.get("uid")
                password = user.get("password")
                jwt = user.get("jwt") or user.get("JWT") or user.get("token")

                if not uid or not password:
                    logger.warning(f"Skipping invalid credential entry (missing uid/password): {user}")
                    continue

                if not jwt:
                    logger.warning(
                        f"No JWT for uid {uid} (server {server_key}). "
                        f"Server will likely return 'Missing JWT (field 8)'."
                    )

                try:
                    token = self._fetch_token(uid, password, jwt, server_key)
                    if token:
                        tokens.append(token)
                except Exception as e:
                    logger.error(f"Error fetching token for {uid} (server {server_key}): {e}")
                    continue

            if tokens:
                self.cache[server_key] = tokens
                logger.info(f"Refreshed tokens for {server_key}. Count: {len(tokens)}")
            else:
                logger.warning(f"No valid tokens retrieved for {server_key}. Clearing cache.")
                self.cache[server_key] = []

        except Exception as e:
            logger.error(f"Critical error during token refresh for {server_key}: {e}")
            if server_key not in self.cache:
                self.cache[server_key] = []

    def _fetch_token(self, uid, password, jwt, server_key):
        """
        Try multiple request shapes so we work with the API regardless of
        whether it expects JWT in query, header, or both.
        """
        params = {"uid": uid, "password": password}
        if jwt:
            params["jwt"] = jwt

        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        if jwt:
            # send in both common header spots
            headers["jwt"] = jwt
            headers["Authorization"] = f"Bearer {jwt}"

        # Attempt 1: GET with query params
        try:
            resp = self.session.get(AUTH_URL, params=params, headers=headers, timeout=8)
            token = self._extract_token(resp)
            if token:
                return token
            self._log_failure(uid, server_key, "GET", resp)
        except Exception as e:
            logger.error(f"GET request failed for {uid}: {e}")

        # Attempt 2: POST with JSON body
        try:
            body = {"uid": uid, "password": password}
            if jwt:
                body["jwt"] = jwt
            resp = self.session.post(
                AUTH_URL, json=body, headers=headers, timeout=8
            )
            token = self._extract_token(resp)
            if token:
                return token
            self._log_failure(uid, server_key, "POST-json", resp)
        except Exception as e:
            logger.error(f"POST(json) request failed for {uid}: {e}")

        # Attempt 3: POST form-encoded
        try:
            body = {"uid": uid, "password": password}
            if jwt:
                body["jwt"] = jwt
            resp = self.session.post(
                AUTH_URL, data=body, headers=headers, timeout=8
            )
            token = self._extract_token(resp)
            if token:
                return token
            self._log_failure(uid, server_key, "POST-form", resp)
        except Exception as e:
            logger.error(f"POST(form) request failed for {uid}: {e}")

        return None

    @staticmethod
    def _extract_token(resp):
        if resp.status_code != 200:
            return None
        try:
            data = resp.json()
        except Exception:
            return None

        # try common shapes
        token = (
            data.get("token")
            or data.get("access_token")
            or data.get("jwt")
        )
        if token:
            return token

        nested = data.get("data") or {}
        if isinstance(nested, dict):
            return (
                nested.get("token")
                or nested.get("access_token")
                or nested.get("jwt")
            )
        return None

    @staticmethod
    def _log_failure(uid, server_key, method, resp):
        try:
            preview = resp.text[:300]
        except Exception:
            preview = "<no body>"
        logger.warning(
            f"[{method}] Failed token fetch for {uid} "
            f"(server {server_key}): status={resp.status_code}, body={preview}"
        )

    def _load_credentials(self, server_key):
        try:
            config_data = os.getenv(f"{server_key}_CONFIG")
            if config_data:
                return json.loads(config_data)

            config_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                "config",
                f"{server_key.lower()}_config.json",
            )
            if os.path.exists(config_path):
                with open(config_path, "r") as f:
                    return json.load(f)

            logger.warning(f"Config file not found for {server_key}: {config_path}")
            return []
        except Exception as e:
            logger.error(f"Error loading credentials for {server_key}: {e}")
            return []


def get_headers(token: str):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        }
