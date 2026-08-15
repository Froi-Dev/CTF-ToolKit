from functools import partial

from anyio import to_thread

from app.analyzers.crypto import RecursiveDecoder
from app.analyzers.crypto.recipe import run_recipe
from app.analyzers.crypto.rsa import analyze_crypto, decrypt_rsa
from app.schemas.crypto import (
    CryptoAnalyzeRequest,
    CryptoAnalyzeResponse,
    DecodeRequest,
    DecodeResponse,
    RecipeRequest,
    RecipeResponse,
    RsaDecryptRequest,
    RsaDecryptResponse,
)


class CryptoDecodeService:
    def __init__(self, analyzer: RecursiveDecoder | None = None) -> None:
        self._analyzer = analyzer or RecursiveDecoder()

    async def decode(self, request: DecodeRequest) -> DecodeResponse:
        # Keep even the bounded CPU search off the event loop.
        return await to_thread.run_sync(partial(self._analyzer.analyze, request))

    async def recipe(self, request: RecipeRequest) -> RecipeResponse:
        return await to_thread.run_sync(partial(run_recipe, request))


class CryptoDecryptService:
    async def analyze(self, request: CryptoAnalyzeRequest) -> CryptoAnalyzeResponse:
        return await to_thread.run_sync(partial(analyze_crypto, request))

    async def rsa_decrypt(self, request: RsaDecryptRequest) -> RsaDecryptResponse:
        return await to_thread.run_sync(partial(decrypt_rsa, request))
