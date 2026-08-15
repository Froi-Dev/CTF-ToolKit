from functools import partial

from anyio import to_thread

from app.analyzers.crypto import RecursiveDecoder
from app.schemas.crypto import DecodeRequest, DecodeResponse


class CryptoDecodeService:
    def __init__(self, analyzer: RecursiveDecoder | None = None) -> None:
        self._analyzer = analyzer or RecursiveDecoder()

    async def decode(self, request: DecodeRequest) -> DecodeResponse:
        # Keep even the bounded CPU search off the event loop.
        return await to_thread.run_sync(partial(self._analyzer.analyze, request))

