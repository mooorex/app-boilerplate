from io import BytesIO
from typing import Union
from utils import hex_to_bytes

from .boilerplate_utils import read, read_uint, read_varint, write_varint, UINT64_MAX


class TransactionError(Exception):
    pass


class Transaction:
    def __init__(self,
                 rawtx: str) -> None:
        self.txinfo: str = rawtx

    def serialize(self) -> bytes:
        return hex_to_bytes(self.txinfo)


    @classmethod
    def from_bytes(cls, hexa: Union[bytes, BytesIO]):
        buf: BytesIO = BytesIO(hexa) if isinstance(hexa, bytes) else hexa

        txinfo_len: int = read_varint(buf)
        txinfo: bytes = read(buf, txinfo_len)

        return cls(txinfo=txinfo)