import io
import struct
from io import BytesIO
from pathlib import Path


class FileIO:
    _sint64 = struct.Struct("<q")
    _uint64 = struct.Struct("<Q")
    _sint32 = struct.Struct("<i")
    _uint32 = struct.Struct("<I")
    _sint16 = struct.Struct("<h")
    _uint16 = struct.Struct("<H")
    _sint8 = struct.Struct("<b")
    _uint8 = struct.Struct("<B")
    _f64 = struct.Struct("<d")
    _f32 = struct.Struct("<f")
    def __init__(self, path: Path | bytes, mode="r+b"):
        self.mode: str = mode
        self.offset: int = 0
        self._isBitesIO = False
        if type(path) is bytes:
            self.path = None
            self.data = bytearray(path)
        else:
            self.data = bytearray(path.read_bytes())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def close(self):
        pass

    def get_buffer(self):
        return self.data

    def tell(self):
        return self.offset

    def seek(self, pos, whence=0):
        size = len(self.data)

        if whence == 0:
            new = pos
        elif whence == 1:
            new = self.offset + pos
        elif whence == 2:
            new = size + pos
        else:
            raise ValueError("invalid whence")

        if not (0 <= new <= size):
            raise ValueError("seek out of bounds")

        self.offset = new

    def read(self, n=-1):
        if n == -1:
            data = self.data[self.offset:]
            self.offset = len(self.data)
        else:
            data = self.data[self.offset:self.offset+n]
            self.offset += n

        return data

    def read_at(self, pos, n=-1):
        current = self.tell()
        self.seek(pos)
        ret = self.read(n)
        self.seek(current)
        return ret

    def write(self, data):
        self.f.write(data)

    def write_at(self, pos, data):
        current = self.tell()
        self.seek(pos)
        self.write(data)
        self.seek(current)

    def peek(self, n):
        pos = self.tell()
        ret = self.read(n)
        self.seek(pos)
        return ret

    def write_line(self, data):
        self.f.write(data + "\n")

    def read_int8(self):
        val = self._sint8.unpack_from(self.data, self.offset)[0]
        self.offset += 1
        return val

    def read_int8_at(self, pos):
        return self._sint8.unpack_from(self.data, pos)[0]

    def read_uint8(self):
        val = self._uint8.unpack_from(self.data, self.offset)[0]
        self.offset += 1
        return val

    def read_uint8_at(self, pos):
        return self._uint8.unpack_from(self.data, pos)[0]

    def read_int16(self):
        val = self._sint16.unpack_from(self.data, self.offset)[0]
        self.offset += 2
        return val

    def read_int16_at(self, pos):
        return self._sint16.unpack_from(self.data, pos)[0]

    def read_uint16(self):
        val = self._uint16.unpack_from(self.data, self.offset)[0]
        self.offset += 2
        return val

    def read_uint16_at(self, pos):
        return self._uint16.unpack_from(self.data, pos)[0]

    def read_int32(self):
        val = self._sint32.unpack_from(self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_int32_at(self, pos):
        return self._sint32.unpack_from(self.data, pos)[0]

    def read_uint32(self):
        val = self._uint32.unpack_from(self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_uint32_at(self, pos):
        return self._uint32.unpack_from(self.data, pos)[0]

    def read_int64(self):
        val = self._sint64.unpack_from(self.data, self.offset)[0]
        self.offset += 8
        return val

    def read_int64_at(self, pos):
        return self._sint64.unpack_from(self.data, pos)[0]

    def read_uint64(self):
        val = self._uint64.unpack_from(self.data, self.offset)[0]
        self.offset += 8
        return val

    def read_uint64_at(self, pos):
        return self._uint64.unpack_from(self.data, pos)[0]

    def read_single(self):
        val = self._f32.unpack_from(self.data, self.offset)[0]
        self.offset += 4
        return val

    def read_single_at(self, pos):
        return self._sint8.unpack_from(self.data, pos)[0]

    def read_double(self):
        val = self._f64.unpack_from(self.data, self.offset)[0]
        self.offset += 8
        return val

    def read_double_at(self, pos):
        return self._f64.unpack_from(self.data, pos)[0]

    def skip_padding(self, alignment):
        while self.tell() % alignment != 0:
            self.read_uint8()

    # Writing is disabled atm
    # def write_int8(self, num):
    #     self.f.write(struct.pack("b", num))

    # def write_int8_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_int8(num)
    #     self.seek(current)

    # def write_uint8(self, num):
    #     self.f.write(struct.pack("B", num))

    # def write_uint8_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_uint8(num)
    #     self.seek(current)

    # def write_int16(self, num):
    #     self.f.write(struct.pack("<h", num))

    # def write_int16_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_int16(num)
    #     self.seek(current)

    # def write_uint16(self, num):
    #     self.f.write(struct.pack("<H", num))

    # def write_uint16_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_uint16(num)
    #     self.seek(current)

    # def write_int32(self, num):
    #     self.f.write(struct.pack("<i", num))

    # def write_int32_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_int32(num)
    #     self.seek(current)

    # def write_uint32(self, num):
    #     self.f.write(struct.pack("<I", num))

    # def write_uint32_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_uint32(num)
    #     self.seek(current)

    # def write_int64(self, num):
    #     self.f.write(struct.pack("<q", num))

    # def write_int64_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_int64(num)
    #     self.seek(current)

    # def write_uint64(self, num):
    #     self.f.write(struct.pack("<Q", num))

    # def write_uint64_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_uint64(num)
    #     self.seek(current)

    # def write_single(self, num):
    #     self.f.write(struct.pack("<f", num))

    # def write_single_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_single(num)
    #     self.seek(current)

    # def write_double(self, num):
    #     self.f.write(struct.pack("<d", num))

    # def write_double_at(self, pos, num):
    #     current = self.tell()
    #     self.seek(pos)
    #     self.write_double(num)
    #     self.seek(current)

    # def write_padding(self, alignment, pad_byte=0x00):
    #     while self.tell() % alignment != 0:
    #         self.write_uint8(pad_byte)
