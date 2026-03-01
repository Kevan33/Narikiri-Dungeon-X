import struct
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self, cast

import lxml.etree as ET
import ndx_tools.formats.tss_instr as instr
import ndx_tools.utils.string as string
from ndx_tools.formats.xml import TlXml
from ndx_tools.utils.fileio import FileIO

_VAR_MAX = 256  # NDX: 256 | TOH: 128 | Vesperia: 512
_STACK_MAX = 512  # NDX: 512 | TOH: 192 | Vesperia: Variable (ints)
_ORDER = ["Place", "Main", "Npc", "Notice"]

_IGNORED_CALLS = {
    # maps
    0x857C, 0x9264, 0x85F8, 0x08D58, 0x08D0C, 0x08D34,
    0x8584, 0x8BDC, 0x953C, 0x08510, 0x094B4, 0x09678,
    0x9D94, 0x7254, 0x7194, 0x65B4,
    # events
    0x7174, 0x6594, 0x6464, 0x41650, 0x4125C, 0x412D8,
}

_TEXT_CALLS = {
    # maps
    0x7894, 0x7888, 0x78A0, 0x8304, 0x7F28, 0x80CC, 0x80B8,
    0x65CC, 0x6F90, 0x8200, 0x746C, 0x85B0, 0x8490, 0x843C,
    0x7290, 0x87CC, 0x8538, 0x81F0, 0x6F44, 0x80B0, 0x8178,
    0x8A58, 0x849C, 0x874C, 0x5F18,
    # events
    0x5E38,
}

@dataclass(slots=True)
class TssText:
    name_off: int
    text_off: int
    name: str
    text: str
    name_len: int = 0xFFFFFFFF


@dataclass
class Tss:
    code_start: int = -1
    entry_start: int = -1
    text_start: int = -1
    interrupt: int = -1
    code_len: int = -1
    text_len: int = -1
    sector_size: int = -1
    instructions: list[instr.Base] = field(default_factory=list)
    ins_int: list[int] = field(default_factory=list)
    functions: dict[int, list[instr.Base]] = field(default_factory=dict)
    labels: set[int] = field(default_factory=set)
    _seen_npc: set[int] = field(default_factory=set)
    text: defaultdict[str, list[TssText]] = field(
        default_factory=lambda: defaultdict(list)
    )
    _f: FileIO = None

    @classmethod
    def from_file(cls, path: Path) -> Self:
        tss = cls()

        with FileIO(path) as f:
            magic = f.read(4)
            if magic != b"TSS\x00":
                raise ValueError("Not a TSS file!")

            tss.code_start = f.read_uint32()
            tss.entry_start = f.read_uint32()
            tss.text_start = f.read_uint32()
            tss.interrupt = f.read_uint32()
            tss.code_len = f.read_uint32()
            tss.text_len = f.read_uint32()
            tss.sector_size = f.read_uint32()
            tss._f = f

            tss.functions[tss.entry_start + tss.interrupt] = []
            if tss.interrupt != 0xFFFFFFFF:
                tss.functions[tss.code_start + tss.interrupt] = []

            # For our purposes we'll always parse the text
            # may change later to only do it when extracting
            tss._parse_text_fast(f.get_buffer())

            # Slow version

            # Collect all instructions
            # tss._parse_instructions(f)

            # Collect all local functions
            # func_off = 0
            # for ins in tss.instructions:
            #     if ins.offset in tss.functions:
            #         func_off = ins.offset

            #     tss.functions[func_off].append(ins)

            # Scan for text sequences
            # tss._scan_funcs()
            return tss

    def make_xml(self, out_path: Path) -> None:
        xml = TlXml()

        for section in _ORDER:
            for text in self.text[section]:
                name = xml.add_name(text.name, text.name_off, text.name_len)
                xml.add_text(section, text.text, text.text_off, name=name)

        out_path.parent.mkdir(parents=True, exist_ok=True)
        xml.save_xml(out_path)

    # in the name of performance, the _fast functions
    # use tuples with the following data:
    # (opcode, value, flags, type, size, is_str)
    def _try_npc_fast(self, ins_name: tuple, ins_body: tuple) -> bool:
        if ins_name[0] != 0x4 and ins_name[0] != 0x3:
            return False
        if ins_body[0] != 0x4 and ins_body[0] != 0x3:
            return False

        if (
            not (ins_name[2] & 0x2)
            or ins_name[3] != instr.DataType.ADDR
            or ins_name[4] != 0x40
        ):
            return False

        if (ins_body[2] & 0xA) != 0xA or ins_body[3] != instr.DataType.S8:
            return False

        name_off = ins_name[1] + self.text_start
        body_off = ins_body[1] + self.text_start

        if name_off in self._seen_npc:
            return True

        self._seen_npc.add(name_off)
        self._f.seek(body_off)
        name_end = self._f.read_uint32() + self.text_start
        total = (name_end - name_off) // 0x40

        for i in range(total):
            namm_off = name_off + 0x10 + (i * 0x40)
            text_off = body_off + i * 4
            name = string.bytes_to_text(self._f, namm_off)
            v = self._f.read_uint32_at(text_off) + self.text_start
            text = string.bytes_to_text(self._f, v)
            t = TssText(namm_off, text_off, name, text, 0x30)
            self.text["Npc"].append(t)

        return True

    def _get_line_fast(self, ins: tuple) -> tuple[int | None, str | None]:
        off = ins[1] + self.text_start
        if ins[0] == 0x2 and ins[5]:
            v = string.bytes_to_text(self._f, off)
            return off, v
        # Never happens
        # if ins[0] == 0x4 or ins[0] == 0x3:
        #     raise ValueError("Line composed of REF instructions")
        return None, None

    def _collect_text_fast(self, section: str, ins: tuple) -> None:
        if ins[0] == 0x4 and ins[3] == instr.DataType.ADDR and ins[4] == 0x18:
            self._read_str_at(self._f, section, ins[1] + self.text_start, ins[0])
        # Never happens
        # if ins[0] == 0x2 or ins[0] == 0x3:
        #     raise ValueError("Bubble composed of LITERAL instructions")

    def _parse_text_fast(self, buf: bytes) -> None:
        code_start = self.code_start
        text_start = self.text_start

        # Unpack all possible 32bit instructions
        total = (text_start - code_start) // 4
        ins_arr = struct.unpack_from(f"<{total}I", buf, code_start)

        _vars = []
        _stk = []
        _rpl = {}

        i = 0
        total = len(ins_arr)

        while i < total:
            ins = ins_arr[i]
            i += 1

            opcode = ins >> 24
            kind = (ins >> 16) & 0xFF

            if opcode == 1: # CALC
                if kind == 0x2A or kind == 0x2B:
                    i += 1
                elif 0x9 < kind < 0x25 or kind == 0x26:
                    _vars.pop()
                elif kind == 0x2C:
                    _vars.pop()
                    _vars.pop()
            elif opcode == 2: # LITERALs
                value = 0
                is_str = bool(kind & 0x80)

                if is_str or kind in (1, 6, 7, 8):
                    value = ins_arr[i]
                    i += 1

                tup = (2, value, 0, 0, 0, is_str)
                _vars.append(tup)
            elif opcode == 3 or opcode == 4: # REF / REF2
                value = ins_arr[i]
                i += 1

                flags = (ins >> 20) & 0xF
                elem_type = (ins >> 16) & 0xF
                elem_size = ins & 0xFFFF

                tup = (opcode, value, flags, elem_type, elem_size, False)
                _vars.append(tup)
            elif opcode == 0x13: # Thread creation
                i += 1
            elif opcode == 5: # Function calls
                value = ins_arr[i]
                i += 1

                arg_count = kind

                if value != 0xFFFFFFFF:
                    # local calls
                    value += code_start - 0xC

                    if arg_count == 3 and value == 0x873C:
                        self._collect_text_fast("Main", _stk[-3])
                    elif arg_count == 5 and value in _TEXT_CALLS:
                        self._collect_text_fast("Main", _stk[-1])

                    del _stk[-arg_count:]

                else:
                    # syscalls
                    target = ins & 0xFFFF

                    if target in (0x0065, 0x014C):
                        text_off, text = self._get_line_fast(_stk[-1])
                        t = TssText(None, text_off, None, text)
                        self.text["Place"].append(t)

                    elif target == 0x0066:
                        if not self._try_npc_fast(_stk[-2], _stk[-1]):
                            self._collect_text_fast("Notice", _stk[-1])
                            name_off, name = self._get_line_fast(_stk[-2])
                            text_off, text = self._get_line_fast(_stk[-1])
                            t = TssText(name_off, text_off, name, text)
                            self.text["Notice"].append(t)

                    elif target == 0xFFFE:
                        s = _stk[-arg_count]
                        if s[0] == 3:
                            _rpl[s[1]] = _stk[-(arg_count - 1)]

                    del _stk[-arg_count:]

                    # PUSH a nop
                    _vars.append((0, 0, 0, 0, 0, False))
            elif opcode in (0x8, 0x9, 0xA, 0x10, 0x11): # JMP / STACK
                i += 1
            elif opcode == 0xE: # PUSH
                v = _vars[-1]
                if v[0] == 3 and v[1] in _rpl:
                    _stk.append(_rpl[v[1]])
                else:
                    _stk.append(v)


    # Naive versions for parsing TSS, they are more clear in intent but
    # get slow for bulk operations
    def _parse_instructions(self, f: FileIO) -> None:
        while f.tell() < self.text_start:
            cmd = f.read_uint32_at(f.tell()) >> 0x18

            match cmd:
                case instr.Type.NOP:
                    ins = instr.NopInstr().parse(f)
                case instr.Type.CALC:
                    ins = instr.CalcInstr().parse(f)
                case instr.Type.LITERAL:
                    ins = instr.LitInstr().parse(f)
                case instr.Type.REF | instr.Type.REF2:
                    ins = instr.RefInstr().parse(f)
                case instr.Type.CALL:
                    ins = instr.CallInstr().parse(f)
                    if ins.kind == instr.CallInstr.Kind.CALL:
                        ins.target += self.code_start - 0xC
                        self.functions[ins.target] = []
                case instr.Type.RETURN | instr.Type.EXIT:
                    ins = instr.RetInstr().parse(f)
                case instr.Type.JMP | instr.Type.JZ | instr.Type.JNZ:
                    ins = instr.BranchInstr().parse(f)
                    ins.target += self.code_start
                    self.labels.add(ins.target)
                case instr.Type.BRANCH | instr.Type.BEQZ | instr.Type.BNEZ:
                    ins = instr.BranchInstr().parse(f)
                    ins.target += f.tell()
                    self.labels.add(ins.target)
                case (
                    instr.Type.PUSH
                    | instr.Type.POP
                    | instr.Type.STACK_FREE
                    | instr.Type.STACK_CLAIM
                ):
                    ins = instr.StackInstr().parse(f)
                case instr.Type.SPAWN:
                    ins = instr.ThreadInstr().parse(f)
                    ins.target += self.code_start - 0xC
                    self.functions[ins.target] = []
                case instr.Type.CAST:
                    ins = instr.CastInstr().parse(f)
                case _:
                    raise ValueError(f"Missing instr type 0x{cmd:02X}")
            self.instructions.append(ins)

    def get_disasm(self) -> str:
        out = []
        out.append('.asciiz "TSS"')
        out.append(".word code_start")
        out.append(f".word {self.entry_start}")
        out.append(f".word {self.text_start}")
        out.append(f".word {self.interrupt}")
        out.append(f".word {self.code_len}")
        out.append(f".word {self.text_len}")
        out.append(f".word {self.sector_size}")
        out.append("")
        out.append("code_start:")

        for ins in self.instructions:
            if ins.offset in self.functions:
                out.append("")
                out.append(f"  func_{ins.offset:06X}_end:")
            elif ins.offset - 0xC in self.functions:
                out.append(f"  func_{ins.offset:06X}:")
            elif ins.offset in self.labels:
                out.append(f"  lbl_{ins.offset:06X}:")
            out.append(ins.get_line())

        return "\n".join(out)

    def _read_str_at(self, f: FileIO, section: str, addr: int, ins: int) -> None:
        if (
            addr is None
            or addr < self.text_start
            or addr >= (self.text_start + self.text_len)
        ):
            raise ValueError("Wrong pointer for string content")

        # Never happens
        # test_val = f.read_uint32_at(addr)
        # if test_val != 1 and test_val != 0:
        #     content = string.bytes_to_text(f, addr)
        #     t = TssText(None, addr, None, content)
        #     raise ValueError("Bubble format unknown!")

        name_pos = f.read_uint32_at(addr + 8)
        text_pos = f.read_uint32_at(addr + 12)

        # Never happens
        # if name_pos == 0 or name_pos >= self.text_start:
        #     raise ValueError("Bubble format invalid!")

        name = string.bytes_to_text(f, self.text_start + name_pos)
        content = string.bytes_to_text(f, self.text_start + text_pos)
        t = TssText(addr + 8, addr + 12, name, content)
        self.text[section].append(t)

    def _try_npc(self, ins_name: instr.Base, ins_body: instr.Base) -> bool:
        # Try to collect NPC-looking instruction sequences
        if ins_name.opcode != 0x4 and ins_name.opcode != 0x3:
            return False
        if ins_body.opcode != 0x4 and ins_body.opcode != 0x3:
            return False

        ins_name: instr.RefInstr = ins_name
        ins_body: instr.RefInstr = ins_body

        # NPC strings are funny, they are just 2 arrays
        # First, an Array of a struct sized 0x40, for the names
        if (
            not (ins_name.flags & 0x2)
            or ins_name.elem_type != instr.DataType.ADDR
            or ins_name.elem_size != 0x40
        ):
            return False

        # Then an array of text pointers
        if (ins_body.flags & 0xA) != 0xA or ins_body.elem_type != instr.DataType.S8:
            return False

        name_off = ins_name.value + self.text_start
        body_off = ins_body.value + self.text_start

        # Don't dump them more than once
        if name_off in self._seen_npc:
            return True

        # There's no indication of size in the instructions
        # themselves, but the name array always comes before
        # the text, so we just do some math to get the count
        self._seen_npc.add(name_off)
        self._f.seek(body_off)
        name_end = self._f.read_uint32() + self.text_start
        total = (name_end - name_off) // 0x40

        # Dump it all!
        for i in range(total):
            namm_off = name_off + 0x10 + (i * 0x40)
            text_off = body_off + i * 4
            name = string.bytes_to_text(self._f, namm_off)
            v = self._f.read_uint32_at(text_off) + self.text_start
            text = string.bytes_to_text(self._f, v)
            t = TssText(namm_off, text_off, name, text, 0x30)
            self.text["Npc"].append(t)

        return True

    def _collect_text(self, section: str, ins: instr.Base) -> None:
        # self.text.append()
        if ins.opcode == 0x2:
            ins = cast("instr.LitInstr", ins)
            if ins.is_str:
                self._read_str_at(self._f, section, ins.value + self.text_start)
        if ins.opcode == 0x4 or ins.opcode == 0x3:
            ins = cast("instr.RefInstr", ins)
            if (ins.imm >> 0x10) == 0xC and (ins.imm & 0xFFFF) == 0x18:
                self._read_str_at(self._f, section, ins.value + self.text_start)

    def _peek_text(self, ins: instr.Base) -> tuple[int | None, str | None]:
        # self.text.append()
        if ins.opcode == 0x2:
            ins = cast("instr.LitInstr", ins)
            if ins.is_str:
                v = string.bytes_to_text(self._f, ins.value + self.text_start)
                return ins.value + self.text_start, v
        if ins.opcode == 0x4 or ins.opcode == 0x3:
            ins = cast("instr.RefInstr", ins)
            if (ins.imm >> 0x10) == 0xC and (ins.imm & 0xFFFF) == 0x18:
                v = string.bytes_to_text(self._f, ins.value + self.text_start)
                return ins.value + self.text_start, v
        return None, None

    def _handle_syscalls(self, ins: instr.CallInstr, _stk: list, _rpl: dict) -> None:
        # Peep syscall args for strigns, other
        # syscalls that aren't included are:
        # 0x00E4 (-1), 0x00C8 (-3), 0x0203 (-1)
        # 0x025A (-5), 0x0276 (-1), 0x02C3 (-2)
        # 0x020E (-2, -1) <- shop person?
        # 0xFFFF (--) <- printf, completely ignored

        if ins.target in (0x0065, 0x014C):  # place names
            self._collect_text("Place", _stk[-1])
        elif ins.target == 0x0066:  # notice-like text
            if not self._try_npc(_stk[-2], _stk[-1]):
                name_off, name = self._peek_text(_stk[-2])
                text_off, text = self._peek_text(_stk[-1])
                t = TssText(name_off, text_off, name, text)
                self.text["Notice"].append(t)
        else:
            if ins.target == 0xFFFE:  # sprintf
                s = _stk[-ins.arg_count]
                if s.opcode == 3:
                    _rpl[s.value] = _stk[-(ins.arg_count - 1)]

            # Consume args for unhandled
            for _ in range(ins.arg_count):
                _stk.pop()

    def _scan_funcs(self) -> None:
        for instructions in self.functions.values():
            _vars = []  # "Registers"
            _stk = []  # stack
            _rpl = {}  # result hack
            for ins in instructions:
                # print(self._collect_text(ins))
                # print(ins.get_line())
                match ins.opcode:
                    case instr.Type.CALC:
                        ins = cast("instr.CalcInstr", ins)
                        match ins.kind:
                            # case ins.Kind.POP:
                            #     _vars.pop()
                            case _ if 0x9 < ins.kind < 0x25:
                                _vars.pop()
                            case ins.Kind.SUBSCRIPT:
                                _vars.pop()
                            case ins.Kind.UNK_2C:
                                _vars.pop()
                                _vars.pop()
                    case instr.Type.LITERAL | instr.Type.REF | instr.Type.REF2:
                        _vars.append(ins)
                    case instr.Type.SPAWN:
                        ins = cast("instr.ThreadInstr", ins)
                        # doesn't seem to ever receive str args?
                        # add logic if text missing
                        pass
                    case instr.Type.CALL:
                        ins = cast("instr.CallInstr", ins)
                        # print(ins.arg_count, _stk[-ins.arg_count:])
                        if ins.kind == ins.Kind.CALL:
                            # Used in skits
                            if ins.arg_count == 3 and ins.target == 0x873C:
                                self._collect_text("Main", _stk[-3])
                            elif ins.arg_count == 5 and ins.target in _TEXT_CALLS:
                                self._collect_text("Main", _stk[-1])

                            for _ in range(ins.arg_count):
                                _stk.pop()
                        else:
                            self._handle_syscalls(ins, _stk, _rpl)
                            _vars.append(instr.NopInstr())
                    case instr.Type.POP:
                        raise ValueError("It does exist!")
                    case instr.Type.PUSH:
                        # Hack to catch the common pattern of:
                        # sprintf(buf, "some %s string", ...)
                        # func("name", buf)
                        if _vars[-1].opcode == 3 and _vars[-1].value in _rpl:
                            _stk.append(_rpl[_vars[-1].value])
                        else:
                            _stk.append(_vars[-1])
