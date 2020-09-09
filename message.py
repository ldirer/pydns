import json
import random
from collections import namedtuple
from pprint import pformat
from typing import List, Union


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
        self.name: List[Label] = []
        # type = RR type code. See "3.2.2. TYPE values". Enables us to interpret rd_data.
        self.type = None
        self.class_ = None
        # ttl for caching purposes (in seconds)
        self.ttl_s = None
        self.rd_length = None
        self.rd_data = None
        self.rd_data_as_labels: List[Label] = []
        self.rd_data_as_ip = ""

    def __repr__(self):
        return json.dumps(
            {
                "name": self.name,
                "type": self.type,
                "class": self.class_,
                "ttl": self.ttl_s,
                "rd_length": self.rd_length,
                "rd_data": self.rd_data.__str__(),
                "rd_data_as_labels": self.rd_data_as_labels,
                "rd_data_as_ip": self.rd_data_as_ip,
            },
            indent=4,
        )

    @staticmethod
    def parse(data: bytes, cursor: int):
        """Note that the RFC I look at does not include ipv6.
        So we can have unexpected values (like type=28, means ipv6 record).
        """
        rr = ResourceRecord()
        rr.name, cursor = parse_labels(data, cursor)
        rr.type, cursor = int.from_bytes(data[cursor : cursor + 2], "big", signed=False), cursor + 2
        rr.class_, cursor = int.from_bytes(data[cursor : cursor + 2], "big", signed=False), cursor + 2
        rr.ttl_s, cursor = int.from_bytes(data[cursor : cursor + 4], "big", signed=False), cursor + 4
        rr.rd_length, cursor = int.from_bytes(data[cursor : cursor + 2], "big", signed=False), cursor + 2

        rr.rd_data, cursor = data[cursor : cursor + rr.rd_length], cursor + rr.rd_length

        if rr.type == QTypes.NS_RECORD:
            rr.rd_data_as_labels, would_be_cursor = parse_labels(data, cursor - rr.rd_length)
            assert would_be_cursor == cursor
        elif rr.type == QTypes.A_RECORD:
            assert rr.rd_length == 4
            c = cursor - rr.rd_length
            ip = str(int.from_bytes(data[c : c + 1], "big", signed=False))
            ip += "." + str(int.from_bytes(data[c + 1 : c + 2], "big", signed=False))
            ip += "." + str(int.from_bytes(data[c + 2 : c + 3], "big", signed=False))
            ip += "." + str(int.from_bytes(data[c + 3 : c + 4], "big", signed=False))
            rr.rd_data_as_ip = ip

        return rr, cursor

    def to_bytes(self):
        return (
            labels_to_bytes(self.name)
            + int_to_bytes(self.type, 2)
            + int_to_bytes(self.class_, 2)
            + int_to_bytes(self.ttl_s, 4)
            + int_to_bytes(self.rd_length, 2)
            + self.rd_data
        )


class Header:
    """https://tools.ietf.org/html/rfc1035 section 4.1"""

    def __init__(self):
        self.transaction_id = 0
        # qr is 0 for query, 1 for response.
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 0
        self.ra = 0
        self.z = 0
        self.rcode = 0
        self.qd_count = 0
        self.an_count = 0
        self.ns_count = 0
        self.ar_count = 0

    @property
    def opcode_nice(self):
        op = int(self.opcode)
        if op == 0:
            return "STANDARD QUERY"
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
            int_to_bytes(self.transaction_id, 2)
            + int_to_bytes(self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd, 1)
            + int_to_bytes(self.ra << 7 | self.z << 4 | self.rcode, 1)
            + int_to_bytes(self.qd_count, 2)
            + int_to_bytes(self.an_count, 2)
            + int_to_bytes(self.ns_count, 2)
            + int_to_bytes(self.ar_count, 2)
        )

    def sanity_check(self):
        assert self.aa in {0, 1}, f"unexpected self.aa={self.aa}"
        assert self.tc in {0, 1}, f"unexpected self.tc={self.tc}"
        # turns out RFC 2535 defines a use for 2 of the 4 bits of z.
        # https://metebalci.com/blog/a-short-practical-tutorial-of-dig-dns-and-dnssec/
        assert self.z >> 2 == 0, f"z reserved for future use should always be 0"
        assert self.rcode in range(6)

    @staticmethod
    def parse_header(data: bytes):
        h = Header()
        h.transaction_id = int.from_bytes(data[:2], "big", signed=False)
        # import pdb; pdb.set_trace()
        h.qr = data[2] >> 7 & 0b1
        h.opcode = data[2] >> 3 & 0b1111
        h.aa = data[2] >> 2 & 0b1
        h.tc = data[2] >> 1 & 0b1
        h.rd = data[2] >> 0 & 0b1
        h.ra = data[3] >> 7 & 0b1
        h.z = data[3] >> 4 & 0b111
        h.rcode = data[3] & 0b1111

        h.qd_count = int.from_bytes(data[4:6], "big", signed=False)
        h.an_count = int.from_bytes(data[6:8], "big", signed=False)
        h.ns_count = int.from_bytes(data[8:10], "big", signed=False)
        h.ar_count = int.from_bytes(data[10:12], "big", signed=False)
        h.sanity_check()

        return h


class Message:
    """A DNS message.

    A DNS message has 5 parts:
        1. Header
        2. Question
        3. Answer
        4. Authority
        5. Additional
    """

    FLAG_QR_RESPONSE = 1
    FLAG_QR_QUERY = 0

    def __init__(self):
        self.header: Header = Header()
        self.question: List[Question] = []
        self.answer: List[ResourceRecord] = []
        self.authority: List[ResourceRecord] = []
        self.additional: List[ResourceRecord] = []
        self.leftover_data = b""

    def __repr__(self):
        return "\n".join([repr(self.header), "================", repr(self.question)])

    def to_bytes(self):
        return (
            self.header.to_bytes()
            + b"".join([q.to_bytes() for q in self.question + self.answer + self.authority + self.additional])
            + self.leftover_data
        )


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
        # I don't think I enforced the 2-byte-long thing anywhere... But it is required.
        # assert len(self.qtype) == len(self.qclass) == 2
        return encoded + int_to_bytes(self.qtype, 2) + int_to_bytes(self.qclass, 2)

    def sanity_check(self):
        # Last label should be the 'top-level domain'
        assert self.qname[-1].n_bytes == 0

    @staticmethod
    def parse_question(data: bytes, cursor: int):
        q = Question()
        q.qname, cursor = parse_labels(data, cursor)
        data = data[cursor:]
        q.qclass = int.from_bytes(data[:2], "big", signed=False)
        q.qtype = int.from_bytes(data[2:4], "big", signed=False)

        return q, cursor + 4


Label = namedtuple("Label", field_names=("n_bytes", "name"))


def parse_labels(data: bytes, cursor: int) -> ([Label], bytes):
    labels = []
    while True:
        len_byte, cursor = data[cursor : cursor + 1], cursor + 1
        if len_byte[0] & 0b11000000 == 0b11000000:
            # this is a pointer to a label (compressed format)
            # We know it's a pointer because of the two '1' bits. We remove them to get the actual value.
            pointer_offset = (
                int.from_bytes(len_byte + data[cursor : cursor + 1], "big", signed=False) & 0b0011111111111111
            )
            cursor = cursor + 1
            other_labels, _ = parse_labels(data, pointer_offset)
            labels.extend(other_labels)
            # we are done with the label list, a pointer is necessarily final (the pointed label list ends with '')
            break
            # raise NotImplementedError("Not handling compressed messages at the moment!")
        else:
            n_bytes = int.from_bytes(len_byte, "big", signed=False)
            name, cursor = data[cursor : cursor + n_bytes].decode(), cursor + n_bytes
            labels.append(Label(n_bytes, name))
            if n_bytes == 0:
                # we reached the 'root' domain
                # The domain name terminates with the zero length octet for the null label of the root.
                break
    return labels, cursor


def labels_to_bytes(labels):
    encoded = b""
    for label in labels:
        encoded += int_to_bytes(label.n_bytes, length=1)
        encoded += label.name.encode()
    return encoded


def parse_questions(data: bytes, cursor: int, qd_count: int):
    questions = []
    for _ in range(qd_count):
        q, cursor = Question.parse_question(data, cursor)
        questions.append(q)
    return questions, cursor


def parse_resource_records(data: bytes, cursor, n):
    rrs = []
    for _ in range(n):
        rr, cursor = ResourceRecord.parse(data, cursor)
        rrs.append(rr)

    return rrs, cursor


def parse_message(data: bytes):
    m = Message()
    header_data, cursor = data[:12], 12
    m.header = Header.parse_header(header_data)
    m.question, cursor = parse_questions(data, cursor, m.header.qd_count)
    m.answer, cursor = parse_resource_records(data, cursor, m.header.an_count)
    m.authority, cursor = parse_resource_records(data, cursor, m.header.ns_count)
    m.additional, cursor = parse_resource_records(data, cursor, m.header.ar_count)

    m.leftover_data = data[cursor:]
    return m


def labels_from_domain(domain: str) -> List[Label]:
    """Construct a set of labels from a domain name."""
    labels = [Label(len(part.encode()), part) for part in domain.split(".")]
    labels.append(Label(0, ""))
    return labels


def domain_from_labels(labels: List[Label]) -> str:
    return ".".join([l.name for l in labels]).rstrip(".")


class QTypes:
    # A record: a host address, 32-bit.
    A_RECORD = 1
    NS_RECORD = 2
    # AAAA record: ipv6 address, 128-bit.
    AAAA_RECORD = 28


class QClasses:
    # 'Internet'
    IN = 1


def construct_query(domain: Union[str, List[Label]]) -> Message:
    """Build a A record query"""
    m = Message()
    # transaction id encoded on 16 bits. Funny, doesn't seem like it's a lot?
    # I would say it's only a limit on concurrent messages handled though.
    m.header.transaction_id = random.randint(1, 65000)
    # mark it as a query
    m.header.qr = Message.FLAG_QR_QUERY
    m.header.qd_count = 1
    q = Question()
    q.qtype = QTypes.A_RECORD  # 'A': a host address
    q.qclass = QClasses.IN  # 'IN': the internet.

    if isinstance(domain, str):
        q.qname = labels_from_domain(domain)
    else:
        # we expect a list of labels
        q.qname = domain
    m.question = [q]
    return m


def construct_response(transaction_id, domain, ip, ttl) -> Message:
    """Return a valid DNS message as response (so that dig and other tools can interpret it).

    'Hardcoded' response construction: we only handle returning a A record.
    """
    response = construct_query(domain)
    response.header.qr = Message.FLAG_QR_RESPONSE
    # recursion desired
    response.header.rd = 1
    # recursion available
    response.header.ra = 1
    response.header.rcode = 0
    response.header.an_count = 1
    response.header.transaction_id = transaction_id
    a = ResourceRecord()
    a.name = domain
    a.type = QTypes.A_RECORD
    a.class_ = QClasses.IN
    a.ttl_s = ttl
    a.rd_length = 4
    a.rd_data = b"".join([int_to_bytes(int(v), 1) for v in ip.split(".")])
    response.answer = [a]
    return response
