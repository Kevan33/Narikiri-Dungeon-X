from dataclasses import dataclass, field
from enum import IntEnum
import struct
from typing import Self

from ndx_tools.utils.fileio import FileIO


def as_u8(x):
    return x & 0xFF

def as_u16(x):
    return x & 0xFFFF

def as_s8(x):
    x &= 0xFF
    return x - 0x100 if x & 0x80 else x

def as_s16(x):
    x &= 0xFFFF
    return x - 0x10000 if x & 0x8000 else x

class DataType(IntEnum):
    TYPE_0 = 0x0
    VOID = 0x1
    U8 = 0x2
    S8 = 0x3
    U16 = 0x4
    S16 = 0x5
    U32 = 0x6
    S32 = 0x7
    F32 = 0x8
    TYPE_9 = 0x9
    TYPE_A = 0xA
    TYPE_B = 0xB
    ADDR = 0xC
    TYPE_D = 0xD
    TYPE_E = 0xE
    TYPE_F = 0xF

class Type(IntEnum):
    NOP = 0x0
    CALC = 0x1
    LITERAL = 0x2
    REF = 0x3
    REF2 = 0x4
    CALL = 0x5
    RETURN = 0x6
    EXIT = 0x7
    JMP = 0x8
    JZ = 0x9
    JNZ = 0xA
    BRANCH = 0xB
    BEQZ = 0xC
    BNEZ = 0xD
    PUSH = 0xE
    POP = 0xF
    STACK_FREE = 0x10
    STACK_CLAIM = 0x11
    DEBUG = 0x12
    SPAWN = 0x13
    CAST = 0x14

@dataclass(slots=True)
class Base:
    offset: int = -1
    bytes: list[int] = field(default_factory=list)
    opcode: int = -1
    imm: int = -1
    size: int = 0

    # Offset is now tracked from outside because calling
    # f.tell() 300 Million times is expensive, actually
    def parse(self, f: FileIO) -> Self:
        self.offset = f.tell()
        v = self.consume_u32(f)
        self.opcode = v >> 0x18
        self.imm = v & 0xFFFFFF
        return self

    def get_bytes_comment(self) -> str:
        content = "".join([f"{x:02X}" for x in self.bytes])
        return f"/* {self.offset:06X} {content: <16} */"

    def get_as_string(self) -> str:
        return "/* InstrBase */"

    def get_line(self) -> str:
        comment = self.get_bytes_comment()
        inst = self.get_as_string()
        return f"    {comment} {inst}"

    def consume_u32(self, f: FileIO) -> int:
        v = f.read(4)
        self.size += 4
        self.bytes.extend(v)
        return int.from_bytes(v, "little")
        return f.read_uint32()

    def consume_s32(self, f: FileIO) -> int:
        v = f.read(4)
        self.size += 4
        self.bytes.extend(v)
        return int.from_bytes(v, "little", signed=True)
        return f.read_int32()

    def consume_f32(self, f: FileIO) -> float:
        v = f.read(4)
        self.size += 4
        self.bytes.extend(v)
        return struct.unpack("<f", v)[0]
        return f.read_single()

@dataclass(slots=True)
class StackInstr(Base):
    class Kind(IntEnum):
        CLAIM = 0
        FREE = 1
        PUSH = 2
        POP = 3

    kind: Kind = 0
    value: int = 0

    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        match self.opcode:
            case 0x0E:
                self.kind = self.Kind.PUSH
                self.value = self.imm & 0xFFFF
            case 0x0F:
                self.kind = self.Kind.POP
            case 0x10:
                self.kind = self.Kind.FREE
                self.value = self.consume_s32(f)
            case 0x11:
                self.kind = self.Kind.CLAIM
                self.value = self.consume_s32(f)
            case _:
                raise ValueError(f"Unknown Stack instruction {self.opcode}")
        return self

    def get_as_string(self) -> str:
        match self.kind:
            case self.Kind.CLAIM:
                return f"CLAIM {self.value}"
            case self.Kind.FREE:
                return f"FREE {self.value}"
            case self.Kind.PUSH:
                if self.value == 0:
                    return "PUSH"
                if self.value & 0x80 or self.value & 0x40:
                    return f"PUSH PTR.{DataType(self.value & 0x0F).name}"
                return f"PUSH {DataType(self.value & 0x0F).name}"
            case self.Kind.POP:
                return "POP"

@dataclass(slots=True)
class CastInstr(Base):
    target: int = 0
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        self.target = (self.imm >> 0x10) & 0xFF
        return self

    def get_as_string(self) -> str:
        s = "CAST PTR." if self.target & 128 != 0 or self.target & 64 != 0 else "CAST "
        return f"{s}{DataType(self.target & 0xf).name}"

@dataclass(slots=True)
class RetInstr(Base):
    class Kind(IntEnum):
        RETURN = 0
        EXIT = 1

    kind: Kind = 0
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        match self.opcode:
            case 0x06:
                self.kind = self.Kind.RETURN
            case 0x07:
                self.kind = self.Kind.EXIT
            case _:
                raise ValueError(f"Unknown Return kind {self.opcode}")

        return self

    def get_as_string(self) -> str:
        match self.kind:
            case self.Kind.RETURN:
                return "RETURN"
            case self.Kind.EXIT:
                return "EXIT"

@dataclass(slots=True)
class RefInstr(Base):
    value: int = 0
    flags: int = 0
    elem_size: int = 0
    elem_type: int = 0
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        self.value = self.consume_s32(f)
        self.elem_size = as_u16(self.imm)
        self.elem_type = (self.imm >> 0x10) & 0xF
        self.flags = (self.imm >> 0x14) & 0xF
        return self

    def get_as_string(self) -> str:
        return f"REF {self.value}"

@dataclass(slots=True)
class NopInstr(Base):
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        return self

    def get_as_string(self) -> str:
        return "NOP"

@dataclass(slots=True)
class BranchInstr(Base):
    class Kind(IntEnum):
        JUMP = 0
        JZ = 1
        JNZ = 2
        BRANCH = 3
        BEQZ = 4
        BNEZ = 5

    kind: Kind = 0
    target: int = 0
    def parse(self, f: FileIO) -> Self:
        super().parse(f)

        if (self.opcode < 0xB):
            self.target = self.consume_s32(f)
        else:
            self.target = as_s16(self.imm)

        match self.opcode:
            case 0x08:
                self.kind = self.Kind.JUMP
            case 0x09:
                self.kind = self.Kind.JZ
            case 0x0A:
                self.kind = self.Kind.JNZ
            case 0x0B:
                self.kind = self.Kind.BRANCH
            case 0x0C:
                self.kind = self.Kind.BEQZ
            case 0x0D:
                self.kind = self.Kind.BNEZ
        return self

    def get_as_string(self) -> str:
        match self.kind:
            case self.Kind.JUMP:
                return f"JMP lbl_{self.target:06X}"
            case self.Kind.JZ:
                return f"JZ lbl_{self.target:06X}"
            case self.Kind.JNZ:
                return f"JNZ lbl_{self.target:06X}"
            case self.Kind.BRANCH:
                return f"B 0x{self.target:06X}"
            case self.Kind.BEQZ:
                return f"BEQZ 0x{self.target:06X}"
            case self.Kind.BNEZ:
                return f"BNEZ 0x{self.target:06X}"

@dataclass(slots=True)
class CallInstr(Base):
    _SYSCALLS = {
        0xFFFF: "printf",
        0xFFFE: "sprintf",
        0xFFFD: "sleep",
        0xFFFC: "wait",
    }
    class Kind(IntEnum):
        CALL = 0
        SYSCALL = 1

    kind: Kind = 0
    target: int = 0
    arg_count: int = 0
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        value = self.consume_s32(f)

        if value == -1:
            self.kind = self.Kind.SYSCALL
            self.target = self.imm & 0xFFFF
            self.arg_count = (self.imm >> 0x10) & 0xFF
        else:
            self.kind = self.Kind.CALL
            self.target = value
            self.arg_count = (self.imm >> 0x10) & 0xFF
        return self

    def get_as_string(self) -> str:
        match self.kind:
            case self.Kind.CALL:
                return f"CALL 0x{self.target:06X} ; {self.arg_count} arg(s)"
            case self.Kind.SYSCALL:
                n = self._SYSCALLS.get(self.target, f"0x{self.target:06X}")
                return f"SYSCALL {n} ; {self.arg_count} arg(s)"

@dataclass(slots=True)
class ThreadInstr(Base):
    class Kind(IntEnum):
        SPAWN = 0

    kind: Kind = 0
    target: int = 0
    arg_count: int = 0
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        value = self.consume_s32(f)

        if value == -1:
            raise ValueError("Can't spawn thread on invalid address")

        self.target = value
        self.arg_count = as_u8(self.imm >> 0x10)
        match self.opcode:
            case 0x13:
                self.kind = self.Kind.SPAWN
        return self

    def get_as_string(self) -> str:
        match self.kind:
            case self.Kind.SPAWN:
                return f"SPAWN 0x{self.target:06X} ; {self.arg_count} arg(s)"

@dataclass(slots=True)
class LitInstr(Base):
    value: int | float = 0
    is_str: bool = False
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        kind = (self.imm >> 0x10)
        self.is_str = False

        if kind & 0x80:
            self.is_str = True
            self.value = self.consume_u32(f)
        else:
            match kind:
                case DataType.U8:
                    self.value = as_u8(self.imm)
                case DataType.S8:
                    self.value = as_s8(self.imm)
                case DataType.U16:
                    self.value = as_u16(self.imm)
                case DataType.S16:
                    self.value = as_s16(self.imm)
                case DataType.U32 | DataType.VOID:
                    self.value = self.consume_u32(f)
                case DataType.S32:
                    self.value = self.consume_s32(f)
                case DataType.F32:
                    self.value = self.consume_f32(f)
                case _:
                    raise ValueError(f"Unknown Type for Literal {kind}")

        return self

    def get_as_string(self) -> str:
        if self.is_str:
            return f"LITERAL STR.{self.value:06X}"
        return f"LITERAL {self.value}"

@dataclass(slots=True)
class CalcInstr(Base):
    class Kind(IntEnum):
        POP               = 0x00,
        POST_INC          = 0x01,
        POST_DEC          = 0x02,
        PRE_INC           = 0x03,
        PRE_DEC           = 0x04,
        UNARY_MINUS       = 0x05,
        UNARY_PLUS        = 0x06,
        BITWISE_NOT       = 0x07,
        LOGICAL_NOT       = 0x08,
        ASSIGN            = 0x09,
        SELF_ADD          = 0x0A,
        SELF_SUB          = 0x0B,
        SELF_MUL          = 0x0C,
        SELF_DIV          = 0x0D,
        SELF_MODULO       = 0x0E,
        SELF_AND          = 0x0F,
        SELF_OR           = 0x10,
        SELF_XOR          = 0x11,
        SELF_SHIFT_LEFT   = 0x12,
        SELF_SHIFT_RIGHT  = 0x13,
        EQUALS            = 0x14,
        NOT_EQUAL         = 0x15,
        LESS_THAN_EQUAL   = 0x16,
        BIGGER_THAN_EQUAL = 0x17,
        BIGGER_THAN       = 0x18,
        LESS_THAN         = 0x19,
        LOGICAL_AND       = 0x1A,
        LOGICAL_OR        = 0x1B,
        MULT              = 0x1C,
        DIV               = 0x1D,
        MOD               = 0x1E,
        ADD               = 0x1F,
        SUB               = 0x20,
        BITWISE_AND       = 0x21,
        BITWISE_OR        = 0x22,
        BITWISE_XOR       = 0x23,
        SHIFT_LEFT        = 0x24,
        SHIFT_RIGHT       = 0x25,
        SUBSCRIPT         = 0x26,
        INDIRECTION       = 0x27,
        ADDRESSOF         = 0x28,
        CAST              = 0x29,
        UNK_2A            = 0x2A,
        STRUCT_FIELD      = 0x2B,
        UNK_2C            = 0x2C

    value: int = 0
    kind: Kind = 0
    def parse(self, f: FileIO) -> Self:
        super().parse(f)
        self.kind = (self.imm >> 0x10) & 0xFF

        match self.kind:
            case 0x2A | 0x2B:
                self.value = self.consume_u32(f)
            # case _:
            #     print(f"Unknown Calc {self.kind}")

        return self

    def get_as_string(self) -> str:
        k = self.Kind(self.kind)
        return f"CALC.{k.name}"
