from collections import namedtuple
from pprint import pformat


def int_to_bytes(i, length):
    return int.to_bytes(i, length, "big", signed=False)


class RCODE:
    # we could find a nicer way to represent this... We'd still want to have RCODE.NO_ERROR be 0.
    mapping = dict(NO_ERROR=0, FORMAT_ERROR=1, SERVER_FAILURE=2, NAME_ERROR=3, NOT_IMPLEMENTED=4, REFUSED=5,)

    reverse_mapping = {v: k for k, v in mapping.items()}

    @classmethod
    def to_string(cls, c):
        return cls.reverse_mapping[c]


class ResourceRecord:
    def __init__(self):
        self.name = []
        self.type = None
        self.class_ = None
        self.ttl_s = None
        self.rd_length = None
        self.rd_data = None

    @staticmethod
    def parse(data: bytes):
        rr = ResourceRecord()
        rr.name, data = parse_labels(data)
        rr.type, data = data[:2], data[2:]
        rr.class_, data = data[:2], data[2:]
        rr.ttl_s, data = int.from_bytes(data[:4], "big", signed=False), data[4:]
        rr.rd_length, data = int.from_bytes(data[:2], "big", signed=False), data[2:]
        rr.rd_data, data = data[: rr.rd_length], data[rr.rd_length :]
        return rr, data

    def to_bytes(self):
        return (
            labels_to_bytes(self.name)
            + self.type
            + self.class_
            + int_to_bytes(self.ttl_s, 4)
            + int_to_bytes(self.rd_length, 2)
            + self.rd_data
        )


class Header:
    """https://tools.ietf.org/html/rfc1035 section 4.1"""

    def __init__(self):
        self.transaction_id = None
        self.qr = None
        self.opcode = None
        self.aa = None
        self.tc = None
        #  SKIPPED FOR NOW:   RD RA Z RCODE
        self.rd = None
        self.ra = None
        self.z = None
        self.rcode = None
        self.qd_count = None
        self.an_count = None
        self.ns_count = None
        self.ar_count = None

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
            {
                f: getattr(self, f)
                for f in [
                    "transaction_id",
                    "qr",
                    "opcode",
                    "opcode_nice",
                    "aa",
                    "tc",
                    "rd",
                    "ra",
                    "z",
                    "rcode",
                    "qd_count",
                    "an_count",
                    "ns_count",
                    "ar_count",
                ]
            }
        )

    def to_bytes(self):
        return (
            self.transaction_id
            + int_to_bytes(self.qr | self.opcode << 1 | self.aa << 5 | self.tc << 6 | self.rd << 7, 1)
            + int_to_bytes(self.ra | self.z << 1 | self.rcode << 4, 1)
            + int_to_bytes(self.qd_count, 2)
            + int_to_bytes(self.an_count, 2)
            + int_to_bytes(self.ns_count, 2)
            + int_to_bytes(self.ar_count, 2)
        )

    def sanity_check(self):
        assert self.aa in {0, 1}, f"unexpected self.aa={self.aa}"
        assert self.tc in {0, 1}, f"unexpected self.tc={self.tc}"
        assert self.z == 0, f"z reserved for future use should always be 0"
        assert self.rcode in range(6)


class Message:
    def __init__(self):
        self.header: Header = Header()
        self.question = []
        self.answer = []
        self.authority = []
        self.additional = []
        self.leftover_data = b""

    def __repr__(self):
        return "\n".join([repr(self.header), "================", repr(self.question)])

    def to_bytes(self):
        return (
            self.header.to_bytes()
            + b"".join([q.to_bytes() for q in self.question + self.answer + self.authority + self.additional])
            + self.leftover_data
        )


def labels_to_bytes(labels):
    encoded = b""
    for label in labels:
        encoded += int_to_bytes(label.n_bytes, length=1)
        encoded += label.name.encode()
    return encoded


class Question:
    """https://tools.ietf.org/html/rfc1035 section 4.1.2"""

    def __init__(self):
        self.qname: [Label] = []
        self.qtype: bytes = b""
        self.qclass: bytes = b""

    def __repr__(self):
        return f"qname={self.qname}\n" f"qtype={self.qtype}\n" f"qclass={self.qclass}\n"

    def to_bytes(self):
        encoded = labels_to_bytes(self.qname)
        return encoded + self.qtype + self.qclass

    def sanity_check(self):
        # Last label should be the 'top-level domain'
        assert self.qname[-1].n_bytes == 0


Label = namedtuple("Label", field_names=("n_bytes", "name"))


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


def parse_labels(data: bytes) -> ([Label], bytes):
    labels = []
    while True:
        len_byte, data = data[:1], data[1:]
        n_bytes = int.from_bytes(len_byte, "big", signed=False)
        name, data = data[:n_bytes].decode(), data[n_bytes:]
        labels.append(Label(n_bytes, name))

        if n_bytes == 0:
            # we reached the 'root' domain
            # The domain name terminates with the zero length octet for the null label of the root.
            break
    return labels, data


def parse_question(data: bytes):
    q = Question()
    q.qname, data = parse_labels(data)
    q.qclass = data[:2]
    q.qtype = data[2:4]

    return q, data[4:]


def parse_questions(data: bytes, qd_count: int):
    questions = []
    for _ in range(qd_count):
        q, data = parse_question(data)
        questions.append(q)
    return questions, data


def parse_header(data: bytes):
    h = Header()
    h.transaction_id = data[:2]
    h.qr = data[2] & 0b1
    h.opcode = data[2] >> 1 & 0b11110
    h.aa = data[2] >> 5 & 0b1
    h.tc = data[2] >> 6 & 0b1
    h.rd = data[2] >> 7 & 0b1
    h.ra = data[3] & 0b1
    h.z = data[3] >> 1 & 0b111
    h.rcode = data[3] >> 4

    h.qd_count = int.from_bytes(data[4:6], "big", signed=False)
    h.an_count = int.from_bytes(data[6:8], "big", signed=False)
    h.ns_count = int.from_bytes(data[8:10], "big", signed=False)
    h.ar_count = int.from_bytes(data[10:12], "big", signed=False)
    h.sanity_check()

    return h


def parse_resource_records(data: bytes, n):
    rrs = []
    for _ in range(n):
        rr, data = ResourceRecord.parse(data)
        rrs.append(rr)

    return rrs, data


def parse_message(data: bytes):
    m = Message()
    header_data, body_data = data[:12], data[12:]
    m.header = parse_header(header_data)
    m.question, data = parse_questions(body_data, m.header.qd_count)
    m.answer, data = parse_resource_records(data, m.header.an_count)
    m.authority, data = parse_resource_records(data, m.header.an_count)
    m.additional, data = parse_resource_records(data, m.header.ar_count)

    m.leftover_data = data
    return m


def test_parse_message():
    # space is b'\x20'
    dig_recurse = (
        b"\\Q\x01 \x00\x01\x00\x00\x00\x00\x00\x01\x07recurse\x03com"
        b"\x00\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x00\x00\x00\x0c"
        b"\x00\n\x00\x08\x86\xd1\xfb\xf9a\xd8+\x15"
    )

    m = parse_message(dig_recurse)
    assert m.header.qd_count == 1
    assert m.header.rcode == 2
    encoded = m.to_bytes()
    assert encoded == dig_recurse


if __name__ == "__main__":
    test_parse_message()
