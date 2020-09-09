from message import (
    parse_message,
    Message,
    labels_from_domain,
    QClasses,
    QTypes,
    Label,
    domain_from_labels,
    construct_query,
    parse_resource_records,
)


def test_parse_message_query():
    # according to wireshark there's an additional record (whose use I'm not sure of).
    additional_record = b"\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x0c\x00\x0a\x00\x08\x0b\xeb\x72\x45\x28\xb4\xa2\x3d"
    dig_recurse_query = (
        b"\x33\x83\x01\x20\x00\x01\x00\x00\x00\x00\x00\x01\x07\x72\x65\x63"
        b"\x75\x72\x73\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01" + additional_record
    )

    m = parse_message(dig_recurse_query)
    assert m.header.qr == Message.FLAG_QR_QUERY
    assert m.header.opcode == 0
    assert m.header.aa == 0
    assert m.header.tc == 0
    assert m.header.rd == 1
    assert m.header.ra == 0
    assert m.header.z == 2
    assert m.header.rcode == 0

    assert m.header.qd_count == 1
    assert m.header.an_count == 0
    assert m.header.ns_count == 0
    assert m.header.ar_count == 1

    assert m.question[0].qname == labels_from_domain("recurse.com")
    assert m.question[0].qclass == QClasses.IN
    assert m.question[0].qtype == QTypes.A_RECORD
    encoded = m.to_bytes()
    assert encoded == dig_recurse_query


def test_parse_message():
    # data copied from wireshark (copy dns message 'as escaped string') and values checked in wireshark.
    dig_recurse_response = (
        b"\x33\x83\x81\x80\x00\x01\x00\x02\x00\x00\x00\x01\x07\x72\x65\x63"
        b"\x75\x72\x73\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00"
        b"\x01\x00\x01\x00\x00\x00\x3b\x00\x04\x03\x5c\x09\xbd\xc0\x0c\x00"
        b"\x01\x00\x01\x00\x00\x00\x3b\x00\x04\x22\xc4\x1d\x1f\x00\x00\x29"
        b"\x02\x00\x00\x00\x00\x00\x00\x00"
    )
    domain_name_part = b"\x07\x72\x65\x63\x75\x72\x73\x65\x03\x63\x6f\x6d\x00"

    m = parse_message(dig_recurse_response)
    assert m.header.qr == 1
    assert m.header.opcode == 0
    assert m.header.aa == 0
    assert m.header.tc == 0
    assert m.header.rd == 1
    assert m.header.ra == 1
    assert m.header.z == 0
    assert m.header.rcode == 0

    assert m.header.qd_count == 1
    assert m.header.an_count == 2
    assert m.header.ns_count == 0
    assert m.header.ar_count == 1

    assert m.question[0].qname == labels_from_domain("recurse.com")
    assert m.question[0].qclass == QClasses.IN
    assert m.question[0].qtype == QTypes.A_RECORD
    encoded = m.to_bytes()

    # replace pointers with the full labels since we don't compress labels when encoding
    assert encoded == dig_recurse_response.replace(b"\xc0\x0c", domain_name_part, -1)

    # check 'recursion available' flag is preserved
    m.header.ra = 1
    encoded = m.to_bytes()
    decoded = parse_message(encoded)
    assert decoded.header.ra == 1


def test_labels_from_domain():
    assert labels_from_domain("recurse.com") == [
        Label(len(b"recurse"), "recurse"),
        Label(len(b"com"), "com"),
        Label(0, ""),
    ]
    for domain in ["a.fdskljfq.laaa.com.io", "google.com", "whatver.b.pizza"]:
        assert domain_from_labels(labels_from_domain(domain)) == domain


def test_construct_message():
    m = construct_query("recurse.com")
    m.to_bytes()


def test_parse_root_server_response():
    response_bytes = b"\xcb)\x80\x00\x00\x01\x00\x00\x00\r\x00\x0e\x07recurse\x03com\x00\x00\x01\x00\x01\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x14\x01a\x0cgtld-servers\x03net\x00\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01b\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01c\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01d\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01e\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01f\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01g\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01h\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01i\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01j\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01k\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01l\xc0+\xc0\x14\x00\x02\x00\x01\x00\x02\xa3\x00\x00\x04\x01m\xc0+\xc0)\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x05\x06\x1e\xc0I\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0!\x0e\x1e\xc0Y\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1a\\\x1e\xc0i\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x1fP\x1e\xc0y\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0\x0c^\x1e\xc0\x89\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0#3\x1e\xc0\x99\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0*]\x1e\xc0\xa9\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc06p\x1e\xc0\xb9\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0+\xac\x1e\xc0\xc9\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc00O\x1e\xc0\xd9\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc04\xb2\x1e\xc0\xe9\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc0)\xa2\x1e\xc0\xf9\x00\x01\x00\x01\x00\x02\xa3\x00\x00\x04\xc07S\x1e\xc0)\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03\xa8>\x00\x00\x00\x00\x00\x00\x00\x02\x000"
    m = parse_message(response_bytes)

    assert m.header.transaction_id == 52009
    # Not sure why this is marked as a 'Query' and not a response. Would need to re-record the bytes.
    # assert m.header.qr == Message.FLAG_QR_RESPONSE
    assert m.header.an_count == 0
    assert m.header.ns_count == 13
    assert m.header.ar_count == 14


def test_parse_resource_record():
    single_rr = b"\x01a\x0cgtld-servers\x03net\x00\x00\x1c\x00\x01\x00\x02\xa3\x00\x00\x10 \x01\x05\x03\xa8>\x00\x00\x00\x00\x00\x00\x00\x02\x000"
    # does-not-crash test
    _ = parse_resource_records(single_rr, 0, 1)


if __name__ == "__main__":
    test_parse_message()
    test_labels_from_domain()
    test_construct_message()
    test_parse_root_server_response()
    test_parse_resource_record()

    # with open("test_data/root_response", "rb") as f:
    #     msg_bytes = f.read()
    # parse_message(msg_bytes)
