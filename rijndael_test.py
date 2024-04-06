import ctypes
from aes.aes import sub_bytes, inv_sub_bytes

rijndael = ctypes.CDLL("./rijndael.so")


def test_sub_bytes():
    py_buffer = [
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0A, 0x0B],
        [0x0C, 0x0D, 0x0E, 0x0F],
    ]
    buffer = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    buffer += b"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    block = ctypes.create_string_buffer(buffer)
    rijndael.sub_bytes(block)
    sub_bytes(py_buffer)
    assert [c for a in py_buffer for c in a] == list(block[:-1])


def test_inv_sub_bytes():
    py_buffer = [
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0A, 0x0B],
        [0x0C, 0x0D, 0x0E, 0x0F],
    ]
    buffer = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    buffer += b"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    block = ctypes.create_string_buffer(buffer)
    rijndael.sub_bytes(block)
    sub_bytes(py_buffer)
    assert [c for a in py_buffer for c in a] == list(block[:-1])
    assert list(block) != list(ctypes.create_string_buffer(buffer))
    rijndael.invert_sub_bytes(block)
    inv_sub_bytes(py_buffer)
    assert [c for a in py_buffer for c in a] == list(block[:-1])
    assert list(block) == list(ctypes.create_string_buffer(buffer))
