"""
structural.py

Contains all structural datatypes
"""
import struct

from abc import ABC
from pyrad.datatypes import base
from pyrad.parser import ParserTLV
from pyrad.utility import tlv_name_to_codes, vsa_name_to_codes

parser_tlv = ParserTLV()

class AbstractStructural(base.AbstractDatatype, ABC):
    """
    abstract class for structural datatypes
    """

class Evs(AbstractStructural):
    """
    structural datatype class for EVS
    """
    def __init__(self, *args, **kwargs):
        super().__init__('evs')

    def encode(self, attribute: 'Attribute', decoded: any) -> bytes:
        pass

    def get_value(self, attribute: 'Attribute', packet: bytes, offset: int,
                  length: int, *args, **kwargs):
        (ext_type, vendor_id, vendor_type) = struct.unpack(
            '!BLB',packet[offset:offset + 6]
        )
        return attribute[ext_type][vendor_id][vendor_type].get_value(
            packet, offset + 6, length - 6
        )

    def print(self, attribute: 'Attribute', decoded: any) -> str:
        sub_attr_strings = [attribute[sub_attr].print(value)
                            for sub_attr, value in decoded.items()]
        return f'{attribute.name} = {{ {', '.join(sub_attr_strings)} }}'


    def parse(self, dictionary: 'Dictionary', string: str) -> any:
        pass

class Extended(AbstractStructural):
    """
    structural datatype class for Extended
    """
    def __init__(self, *args, **kwargs):
        super().__init__('extended')

    def encode(self, attribute: 'Attribute', decoded: any) -> bytes:
        pass

    def get_value(self, attribute: 'Attribute', packet: bytes, offset: int,
                  length: int, *args, **kwargs):
        ext_type = struct.unpack('!B', packet[offset:offset + 1])[0]
        return attribute[ext_type].get_value(packet, offset + 1, length - 1)

    def print(self, attribute: 'Attribute', decoded: any) -> str:
        sub_attr_strings = [attribute[sub_attr].print(value)
                            for sub_attr, value in decoded.items()]
        return f'{attribute.name} = {{ {', '.join(sub_attr_strings)} }}'

    def parse(self, dictionary: 'Dictionary', string: str) -> any:
        pass

class LongExtended(AbstractStructural):
    """
    structural datatype class for Long-Extended
    """
    def __init__(self, *args, **kwargs):
        super().__init__('long-extended')

    def encode(self, attribute: 'Attribute', decoded: any) -> bytes:
        pass

    def get_value(self, attribute: 'Attribute', packet: bytes, offset: int,
                  length: int, *args, **kwargs):
        value = b''
        byte_read = 0

        (ext_type, flags) = struct.unpack('!BB', packet[offset:offset + 2])

        # build the type oid and compare with previous fragment, if exists
        oid = (attribute.number, ext_type)
        if 'prev_oid' in kwargs and kwargs['prev_oid'] != oid:
            raise ValueError('Inconsistent types in long extended fragments')

        # adds value from current fragment to value
        value  += packet[offset + 2:offset + length]
        byte_read += length

        # check for more flag (left most bit of flags header)
        # perform bitwise shift to check
        if flags >> 7:
            # peel off headers from next fragment
            _, next_length = struct.unpack(
                '!BB', packet[offset + length:offset + length + 2]
            )
            # we need to add the headers into the number of bytes we've read
            byte_read += 2

            # use nested calls to grab next value in next fragment
            value, next_frag_len = attribute.get_value(
                packet, offset + length + 2, next_length, prev_oid = oid
            )
            byte_read += next_frag_len

        # check to see if it's the first fragment.
        # only the first fragment wouldn't have prev_oid passed in as a kwarg
        if 'prev_oid' not in kwargs:
            # perform the "decoding" here since we should now have the entire
            # byte string that spanned across multiple fragments
            # since get_value always expects a packet, we just pretend that the
            # encapsulated value is a packet that we can call get_value on
            return attribute[ext_type].get_value(value, 0, len(value)), byte_read
        # if this is not the starting fragment, return the raw value
        return value, byte_read

    def print(self, attribute: 'Attribute', decoded: any) -> str:
        pass

    def parse(self, dictionary: 'Dictionary', string: str) -> any:
        pass

class Tlv(AbstractStructural):
    """
    structural datatype class for TLV
    """
    def __init__(self, *args, **kwargs):
        super().__init__('tlv')

    def encode(self, attribute, decoded):
        encoding = b''
        for key, value in decoded.items():
            encoding += attribute.children[key].encode(value)

        if len(encoding) + 2 > 255:
            raise ValueError('TLV length too long for one packet')

        return (struct.pack('!B', attribute.number)
                + struct.pack('!B', len(encoding) + 2)
                + encoding)

    def get_value(self, attribute: 'Attribute', packet, offset, length, *args,
                  **kwargs):
        tlvs = {}

        if length < 3:
            raise ValueError('TLV length too short')
        if offset + length > len(packet):
            raise ValueError('TLV length too long')

        cursor = offset
        while cursor < offset + length:
            (sub_type, sub_len) = struct.unpack(
                '!BB', packet[cursor:cursor + 2]
            )

            if sub_len < 3:
                raise ValueError('TLV length field too small')

            sub_value, sub_offset = attribute[sub_type].get_value(
                packet, cursor + 2, sub_len - 2
            )
            tlvs.setdefault(sub_type, []).append(sub_value)

            # move cursor forward by additional two to account for headers
            cursor += sub_offset + 2
        return tlvs, length

    def print(self, attribute, decoded):
        sub_attr_strings = [attribute[sub_attr].print(value)
                            for sub_attr, value in decoded.items()]
        return f"{attribute.name} = {{ {', '.join(sub_attr_strings)} }}"

    def parse(self, dictionary, string):
        return tlv_name_to_codes(dictionary, parser_tlv.parse(string))

class Vsa(AbstractStructural):
    """
    structural datatype class for VSA
    """
    def __init__(self, *args, **kwargs):
        super().__init__('vsa')

        #  used for get_value()
        self.tlv = Tlv()

    def encode(self, attribute, decoded):
        encoding = b''

        for key, value in decoded.items():
            encoding += attribute.children[key].encode(value)

        return (struct.pack('!B', attribute.number)
                + struct.pack('!B', len(encoding) + 4)
                + struct.pack('!L', attribute.vendor)
                + encoding)

    def get_value(self, attribute: 'Attribute', packet, offset, length, *args,
                  **kwargs):
        tlvs = {}

        # minimum 4 bytes for vendor-id + 3 bytes for 1 tlv
        if length < 7:
            return {packet[offset:offset + length]: {}}, length

        vendor = struct.unpack('!L', packet[offset:offset + 4])[0]

        # move cursor past vendor, start at first TLV
        cursor = offset + 4
        while cursor < offset + length:
            (sub_type, sub_length) = struct.unpack('!BB', packet[cursor:cursor + 2])

            tlvs[sub_type], sub_offset = attribute[vendor][
                sub_type].get_value(packet, cursor + 2, sub_length - 2)
            cursor += sub_offset + 2

        return {vendor: tlvs}, length

    def print(self, attribute, decoded):
        sub_attr_strings = [attribute[sub_attr].print(value)
                            for sub_attr, value in decoded.items()]
        return f"Vendor-Specific = {{ {attribute.vendor} = {{ {', '.join(sub_attr_strings)} }}"

    def parse(self, dictionary, string):
        return vsa_name_to_codes(dictionary, parser_tlv.parse(string))
