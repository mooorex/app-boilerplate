from io import BytesIO
from typing import Union

from .boilerplate_utils import read, read_uint, read_varint, write_varint, UINT64_MAX


class PersonalMsgError(Exception):
    pass


class PersonalMsg:
    def __init__(self,
                 personalmsg: str) -> None:
        self.personalmsg: bytes = personalmsg.encode('utf-8')


    def serialize(self) -> bytes:
        return b"".join([
            self.personalmsg
        ])

    @classmethod
    def from_bytes(cls, hexa: Union[bytes, BytesIO]):
        buf: BytesIO = BytesIO(hexa) if isinstance(hexa, bytes) else hexa


        personalmsg: str = read(buf).decode('utf-8')
        return cls(personalmsg=personalmsg)