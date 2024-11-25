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

class Tlv(AbstractStructural):
    """
    structural datatype class for TLV
    """
    def __init__(self):
        super().__init__('tlv')

    def encode(self, attribute, decoded, *args, **kwargs):
        encoding = b''
        for key, value in decoded.items():
            encoding += attribute.sub_attributes[key].encode(value, )

        if len(encoding) + 2 > 255:
            raise ValueError('TLV length too long for one packet')

        return (struct.pack('!B', attribute.code)
                + struct.pack('!B', len(encoding) + 2)
                + encoding)

    def get_value(self, attribute: 'Attribute', packet, offset, *args,
                  **kwargs):
        sub_attrs = {}

        _, outer_len = struct.unpack('!BB', packet[offset:offset + 2])[0:2]

        if outer_len < 3:
            raise ValueError('TLV length too short')
        if offset + outer_len > len(packet):
            raise ValueError('TLV length too long')

        # move cursor to TLV value
        cursor = offset + 2
        while cursor < offset + outer_len:
            sub_type, sub_len = struct.unpack(
                '!BB', packet[cursor:cursor + 2]
            )[0:2]

            if sub_len < 3:
                raise ValueError('TLV length field too small')

            value, subattr_offset = attribute.sub_attributes[sub_type].type.get_value(
                attribute, packet, cursor)
            sub_attrs.setdefault(sub_type, []).append(value)
            cursor += subattr_offset
        return sub_attrs, outer_len

    def print(self, attribute, decoded, *args, **kwargs):
        sub_attr_strings = [sub_attr.print()
                            for sub_attr in attribute.sub_attributes]
        return f"{attribute.name} = {{ {', '.join(sub_attr_strings)} }}"

    def parse(self, dictionary, string, *args, **kwargs):
        return tlv_name_to_codes(dictionary, parser_tlv.parse(string))

class Vsa(AbstractStructural):
    """
    structural datatype class for VSA
    """
    def __init__(self):
        super().__init__('vsa')

    def encode(self, attribute, decoded, *args, **kwargs):
        encoding = b''

        for key, value in decoded.items():
            encoding += attribute.sub_attributes[key].encode(value, )

        return (struct.pack('!B', attribute.code)
                + struct.pack('!B', len(encoding) + 4)
                + struct.pack('!L', attribute.vendor)
                + encoding)

    def get_value(self, attribute, packet, offset, *args, **kwargs):
        sub_attrs = {}

        _, outer_len = struct.unpack(
            '!BB', packet[offset:offset + 2]
        )[0:2]

        if outer_len < 8:
            #  in malformed packets, take everything after the outlet len as
            #  the vendor name and set the tlv to be empty
            return {packet[offset + 2:offset + outer_len]: {}}, outer_len
        if offset + outer_len > len(packet):
            raise ValueError('VSA length too long')

        vendor_id = struct.unpack('!L', packet[offset + 2:offset + 6])[0]

        cursor = offset + 6
        while cursor < offset + outer_len:
            sub_type, sub_len = struct.unpack(
                '!BB', packet[cursor:cursor + 2]
            )[0:2]

            if sub_len < 3:
                raise ValueError('TLV length field too small')

            sub_attr = attribute.sub_attributes[vendor_id][sub_type]

            value, offset = sub_attr.type.get_value(sub_attr, packet, cursor)
            sub_attrs.setdefault(sub_type, []).append(value)
            cursor += offset

        return {vendor_id: sub_attrs}, outer_len

    def print(self, attribute, decoded, *args, **kwargs):
        sub_attr_strings = [sub_attr.print()
                            for sub_attr in attribute.sub_attributes]
        return f"Vendor-Specific = {{ {attribute.vendor} = {{ {', '.join(sub_attr_strings)} }}"

    def parse(self, dictionary, string, *args, **kwargs):
        return vsa_name_to_codes(dictionary, parser_tlv.parse(string))
