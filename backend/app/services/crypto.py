from functools import partial

from anyio import to_thread

from app.analyzers.crypto import RecursiveDecoder
from app.analyzers.crypto.openssl_enc import analyze_openssl_enc, decrypt_openssl_enc
from app.analyzers.crypto.recipe import run_recipe
from app.analyzers.crypto.rsa import analyze_crypto, decrypt_rsa
from app.analyzers.crypto.symmetric import SymmetricAnalyzer, SymmetricAnalyzeInput
from app.analyzers.crypto.stream import StreamAnalyzer, StreamAnalyzeInput
from app.analyzers.crypto.hash import HashAnalyzer, HashAnalyzeInput
from app.analyzers.crypto.custom import CustomEncryptionAnalyzer, CustomAnalyzeInput
from app.schemas.crypto import (
    CryptoAnalyzeRequest,
    CryptoAnalyzeResponse,
    DecodeRequest,
    DecodeResponse,
    RecipeRequest,
    RecipeResponse,
    OpenSslAnalyzeRequest,
    OpenSslAnalyzeResponse,
    OpenSslDecryptRequest,
    OpenSslDecryptResponse,
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

    async def openssl_analyze(self, request: OpenSslAnalyzeRequest) -> OpenSslAnalyzeResponse:
        return await to_thread.run_sync(partial(analyze_openssl_enc, request))

    async def openssl_decrypt(self, request: OpenSslDecryptRequest) -> OpenSslDecryptResponse:
        return await to_thread.run_sync(partial(decrypt_openssl_enc, request))

    async def symmetric_analyze(self, request: SymmetricAnalyzeInput):
        analyzer = SymmetricAnalyzer()
        return await to_thread.run_sync(partial(analyzer.analyze, request))

    async def stream_analyze(self, request: StreamAnalyzeInput):
        analyzer = StreamAnalyzer()
        return await to_thread.run_sync(partial(analyzer.analyze, request))

    async def hash_analyze(self, request: HashAnalyzeInput):
        analyzer = HashAnalyzer()
        return await to_thread.run_sync(partial(analyzer.analyze, request))

    async def custom_analyze(self, request: CustomAnalyzeInput):
        analyzer = CustomEncryptionAnalyzer()
        return await to_thread.run_sync(partial(analyzer.analyze, request))
