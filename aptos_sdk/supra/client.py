import httpx

from aptos_sdk.async_client import ClientConfig, RestClient
from aptos_sdk.supra.accounts import AccountAPI


class SupraClient:
    """Main Supra Client"""

    def __init__(self, base_url: str, client_config: ClientConfig = ClientConfig()):
        self.base_url = base_url.rstrip("/")
        self.client_config = client_config

        # Default `http` client for Supra
        header = {"User-agent": "supra-python-sdk/1.0.0"}
        if client_config.api_key:
            header["Authorization"] = f"Bearer {client_config.api_key}"

        self._http_client = httpx.AsyncClient(
            http2=client_config.http2,
            header=header,
            timeout=httpx.Timeout(60.0, pool=None),
        )

        # Aptos client for backward compatibility
        self._aptos_client = RestClient(base_url, client_config)

        # initialize undelying endpoints
        self.accounts = AccountAPI(self._http_client, self.base_url)

    @property
    def aptos(self) -> RestClient:
        """Access underlying Aptos client."""
        return self._aptos_client

    async def close(self):
        """Close all connections."""
        self._aptos_client.close()
        self._http_client.aclose()

    async def chain_id(self) -> int:
        return self._aptos_client.chain_id()

    async def info(self):
        return self._aptos_client.info()
