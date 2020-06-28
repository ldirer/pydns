from collections import namedtuple
from pprint import pprint, pformat


class Header:
    def __init__(self):
        self.transaction_id = None
        self.qr = None
        self.opcode = None
        self.aa = None
        self.tc = None
        #     RD RA Z RCODE
        self.qd_count = None

    @property
    def opcode_nice(self):
        op = int(self.opcode)
        if op == 0:
            return "QUERY"
        elif op == 1:
            return "IQUERY"
        elif op == 2:
            return "STATUS"
        elif 3 <= op <= 15:
            return "RESERVED"
        else:
            raise ValueError(f"unexpected value for 4-bit opcode: {self.opcode}")

    def __repr__(self):
        return pformat(
            {f: getattr(self, f) for f in ["transaction_id", "qr", "opcode", "opcode_nice", "aa", "tc", "qd_count"]}
        )


class Message:
    def __init__(self):
        self.header: Header = None
        self.questions = []

    def __repr__(self):
        return "\n".join([repr(self.header), "================", repr(self.questions)])


class Question:
    """https://tools.ietf.org/html/rfc1035 section 4.1.2"""

    def __init__(self):
        self.qname: [Label] = []
        self.qtype = None
        self.qclass = None

    def __repr__(self):
        return f"qname={self.qname}\n" f"qtype={self.qtype}\n" f"qclass={self.qclass}\n"


Label = namedtuple("n_bytes", "name")

# # Maybe for nicer syntax?
# class Parser:
#
#     def __init__(self, data):
#         self.data = data
#
#     def take(self, n_bytes):
#         r, self.data = self.data[:n_bytes], self.data[n_bytes:]
#         return
#


def parse_question(data: bytes):
    q = Question()
    while True:
        len_byte, data = data[:1], data[1:]
        n_bytes = int.from_bytes(len_byte, "big", signed=False)
        name, data = data[:n_bytes].decode(), data[n_bytes:]
        q.qname.append(Label((n_bytes, name)))

        if n_bytes == 0:
            # we reached the 'root' domain
            # The domain name terminates with the zero length octet for the null label of the root.
            break
    q.qclass = data[:2]
    q.qtype = data[2:4]

    return q, data[4:]


def parse_questions(data: bytes, qd_count: int):
    for _ in range(qd_count):
        q, data = parse_question(data)
    return [q for _ in range(qd_count)]


def parse_header(data: bytes):
    h = Header()
    h.transaction_id = data[:2]
    h.qr = data[2] & 0b1
    h.opcode = data[2] & 0b11110
    h.aa = data[2] & 0b100000 != 0
    h.tc = data[2] & 0b1000000 != 0

    import pdb; pdb.set_trace()
    h.qd_count = int.from_bytes(data[4:6], "big", signed=False)
    return h


def parse_message(data: bytes):
    m = Message()
    header_data, body_data = data[:12], data[12:]
    m.header = parse_header(header_data)
    m.questions = parse_questions(body_data, m.header.qd_count)
    return m


def test_parse_message():
    dig_recurse = b"\xa7F\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x07recurse\x03com\x00\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x0c\x00\n\x00\x08\xdf\x17z\x83\x8d\x01\xa0^"
    m = parse_message(dig_recurse)
    print(f"PARSED INTO {m}")


if __name__ == "__main__":
    test_parse_message()
