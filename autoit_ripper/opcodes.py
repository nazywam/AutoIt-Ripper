from .autoit_data import FUNCTIONS, KEYWORDS, MACROS
from .utils import ByteStream

KEYWORDS_INVERT_CASE = {i.upper(): i for i in KEYWORDS}
FUNCTIONS_INVERT_CASE = {i.upper(): i for i in FUNCTIONS}
MACROS_INVERT_CASE = {i.upper(): i for i in MACROS}


class TokenStream(ByteStream):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.indent = 0
        self.next_indent = 0

    def get_xored_string(self) -> str:
        key = self.u32()
        if key > len(self._data):
            raise Exception("Read xor string out of bounds")

        ret = bytearray(key * 2)
        for i in range(key):
            c = self.u16() ^ key
            ret[i * 2 + 0] = c & 0xFF
            ret[i * 2 + 1] = (c >> 8) & 0xFF
        return ret.decode("utf-16")

    def peek_next_opcode(self) -> int:
        return self._data[self._offset]


def escape_string(string: str) -> str:
    # escape double qutoes
    string = string.replace('"', '""')
    return f'"{string}"'


def apply_keyword_indent(stream: TokenStream, keyword: str) -> None:
    if keyword in ("While", "Do", "For", "Select", "Switch", "Func", "If"):
        stream.next_indent += 1

    if keyword in ("Case", "Else", "ElseIf"):
        stream.indent -= 1

    if keyword in (
        "WEnd",
        "Until",
        "Next",
        "EndSelect",
        "EndSwitch",
        "EndFunc",
        "EndIf",
    ):
        stream.next_indent -= 1
        stream.indent -= 1

    if keyword in ("Then",):
        if stream.peek_next_opcode() != 0x7F:
            stream.next_indent -= 1

    if keyword in ("EndFunc",):
        stream.next_indent = 0


def read_keyword_id(stream: TokenStream) -> str:
    keyword_no = stream.i32()
    if keyword_no > len(KEYWORDS):
        raise Exception("Token not found")

    keyword = KEYWORDS[keyword_no]
    apply_keyword_indent(stream, keyword)
    return keyword


def read_keyword(stream: TokenStream) -> str:
    keyword = KEYWORDS_INVERT_CASE[stream.get_xored_string()]
    apply_keyword_indent(stream, keyword)
    return keyword


OPCODES = {
    # Keyword
    0x00: read_keyword_id,
    # Function
    0x01: lambda x: FUNCTIONS[x.i32()],
    # Numbers
    0x05: lambda x: str(x.u32()),
    0x10: lambda x: str(x.u64()),
    0x20: lambda x: str(x.f64()),
    # Statements
    0x30: read_keyword,
    0x31: lambda x: FUNCTIONS_INVERT_CASE[x.get_xored_string()],
    0x32: lambda x: "@" + MACROS_INVERT_CASE[x.get_xored_string()],
    0x33: lambda x: "$" + x.get_xored_string(),
    0x34: lambda x: x.get_xored_string(),
    0x35: lambda x: "." + x.get_xored_string(),
    0x36: lambda x: escape_string(x.get_xored_string()),
    0x37: lambda x: x.get_xored_string(),
    # Operators
    0x40: lambda x: ",",
    0x41: lambda x: "=",
    0x42: lambda x: ">",
    0x43: lambda x: "<",
    0x44: lambda x: "<>",
    0x45: lambda x: ">=",
    0x46: lambda x: "<=",
    0x47: lambda x: "(",
    0x48: lambda x: ")",
    0x49: lambda x: "+",
    0x4A: lambda x: "-",
    0x4B: lambda x: "/",
    0x4C: lambda x: "*",
    0x4D: lambda x: "&",
    0x4E: lambda x: "[",
    0x4F: lambda x: "]",
    0x50: lambda x: "==",
    0x51: lambda x: "^",
    0x52: lambda x: "+=",
    0x53: lambda x: "-=",
    0x54: lambda x: "/=",
    0x55: lambda x: "*=",
    0x56: lambda x: "&=",
    0x57: lambda x: "?",
    0x58: lambda x: ":",
}


def deassemble_script(script_data: bytes, indent_lines: bool = True) -> str:
    stream = TokenStream(script_data)

    lines_no = stream.u32()
    current_line = 0

    INDENT_STR = "\t" if indent_lines else ""

    out = []
    line_items = []

    while current_line < lines_no:
        opcode = stream.u8()
        if opcode in OPCODES:
            line_items.append(OPCODES[opcode](stream))

        elif opcode == 0x7F:
            current_line += 1
            final_line = INDENT_STR * stream.indent + " ".join(line_items) + "\r\n"
            line_items = []
            stream.indent = stream.next_indent
            out.append(final_line)
        else:
            raise Exception(f"Unsupported opcode: {hex(opcode)}")

    return "".join(out)
