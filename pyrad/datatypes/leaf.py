"""
leaf.py

Contains all leaf datatypes (ones that can be encoded and decoded directly)
"""
import binascii
import struct
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Network, IPv6Address, IPv4Network, \
    AddressValueError

from netaddr import EUI, core

from pyrad.datatypes import base


class AbstractLeaf(base.AbstractDatatype, ABC):
    """
    abstract class for leaf datatypes
    """
    @abstractmethod
    def decode(self, raw: bytes, *args, **kwargs) -> any:
        """
        python datat structure from bytestring
        :param raw: raw attribute value
        :type raw: bytes
        :param args:
        :param kwargs:
        :return: python data structure
        :rtype: any
        """
        """
        turns bytes into python data structure

        :param *args:
        :param **kwargs:
        :param raw: bytes
        :return: python data structure
        """

    def get_value(self, attribute, packet, offset, length, *args, **kwargs):
        return packet[offset:offset + length], length

class AscendBinary(AbstractLeaf):
    """
    leaf datatype class for ascend binary
    """
    def __init__(self, *args, **kwargs):
        super().__init__('abinary')

    def encode(self, attribute, decoded):
        terms = {
            'family': b'\x01',
            'action': b'\x00',
            'direction': b'\x01',
            'src': b'\x00\x00\x00\x00',
            'dst': b'\x00\x00\x00\x00',
            'srcl': b'\x00',
            'dstl': b'\x00',
            'proto': b'\x00',
            'sport': b'\x00\x00',
            'dport': b'\x00\x00',
            'sportq': b'\x00',
            'dportq': b'\x00'
        }

        family = 'ipv4'
        for t in decoded.split(' '):
            key, value = t.split('=')
            if key == 'family' and value == 'ipv6':
                family = 'ipv6'
                terms[key] = b'\x03'
                if terms['src'] == b'\x00\x00\x00\x00':
                    terms['src'] = 16 * b'\x00'
                if terms['dst'] == b'\x00\x00\x00\x00':
                    terms['dst'] = 16 * b'\x00'
            elif key == 'action' and value == 'accept':
                terms[key] = b'\x01'
            elif key == 'action' and value == 'redirect':
                terms[key] = b'\x20'
            elif key == 'direction' and value == 'out':
                terms[key] = b'\x00'
            elif key in ('src', 'dst'):
                if family == 'ipv4':
                    ip = IPv4Network(value)
                else:
                    ip = IPv6Network(value)
                terms[key] = ip.network_address.packed
                terms[key + 'l'] = struct.pack('B', ip.prefixlen)
            elif key in ('sport', 'dport'):
                terms[key] = struct.pack('!H', int(value))
            elif key in ('sportq', 'dportq', 'proto'):
                terms[key] = struct.pack('B', int(value))

        trailer = 8 * b'\x00'

        result = b''.join(
            (terms['family'], terms['action'], terms['direction'], b'\x00',
             terms['src'], terms['dst'], terms['srcl'], terms['dstl'],
             terms['proto'], b'\x00',
             terms['sport'], terms['dport'], terms['sportq'], terms['dportq'],
             b'\x00\x00', trailer))
        return result

    def decode(self, raw, *args, **kwargs):
        #  just return the raw binary string
        return raw

    def print(self, attribute, decoded):
        #  the binary string is what we are looking for
        return decoded


    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        # abinary strings are stored as strings, so parse and return as is
        return string

class Bool(AbstractLeaf):
    """
    leaf datatype class for boolean datatype
    """
    def __init__(self, *args, **kwargs):
        super().__init__('bool')

    def encode(self, attribute, decoded):
        # convert boolean into int, then encode into bytestring
        return struct.pack('!B', int(decoded))

    def decode(self, raw, *args, **kwargs):
        # unpack bytes into int, then convert into boolean
        return bool(struct.unpack('!B', raw)[0])

    def print(self, attribute, decoded):
        # convert bool into string, then return
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        match string.lower():
            case 'true':
                return True
            case 'false':
                return False
            case _:
                raise TypeError('Failed to parse bool value')

class Byte(AbstractLeaf):
    """
    leaf datatype class for bytes (1 byte unsigned int)
    """
    def __init__(self, *args, **kwargs):
        super().__init__('byte')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as byte') from exc
        return struct.pack('!B', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!B', raw)[0]

    def print(self, attribute, decoded):
        #  cast int to string before returning
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as byte') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for byte')
            if num > 255:
                raise ValueError('Parsed value too large for byte')
            return num

class ComboIp(AbstractLeaf):
    """
    leaf datatype class for combo ip
    """
    def __init__(self, *args, **kwargs):
        super().__init__('combo-ip')

        self.ipv4 = Ipaddr()
        self.ipv6 = Ipv6addr()

    def encode(self, attribute, decoded):
        if not isinstance(decoded, str):
            raise TypeError(f'Can not encode non-string as combo-ip')
        # since IPv4 and IPv6 addresses are stored as strings, so should
        # combo-p be. As such, we can simply check if the IP address contains
        # a '.' to know if we are working with an IPv4 or IPv6 address
        # simply use the pre-existing encode functions to encode the value
        if len(decoded.split('.')) == 4:
            return self.ipv4.encode(attribute, decoded)
        return self.ipv6.encode(attribute, decoded)

    def decode(self, raw: bytes, *args, **kwargs) -> any:
        # based on the number of bytes, we know what we are working with
        match len(raw):
            case 4:
                return self.ipv4.decode(raw)
            case 16:
                return self.ipv6.decode(raw)
            case _:
                raise ValueError('Invalid number of bytes for combo-ip')

    def print(self, attribute, decoded):
        # since we store the IP as a string, just return it
        return decoded

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        # try to parse as ipv4 first, if failed, try as ipv6
        try:
            return IPv4Address(string).exploded
        except AddressValueError:
            try:
                return IPv6Address(string).exploded
            except AddressValueError as e:
                raise TypeError(f'Parsing invalid combo-ip address') from e

class Date(AbstractLeaf):
    """
    leaf datatype class for dates
    """
    def __init__(self, *args, **kwargs):
        super().__init__('date')

    def encode(self, attribute, decoded):
        if not isinstance(decoded, int):
            raise TypeError('Can not encode non-integer as date')
        return struct.pack('!I', decoded)

    def decode(self, raw, *args, **kwargs):
        #  dates are stored as ints
        return (struct.unpack('!I', raw))[0]

    def print(self, attribute, decoded):
        #  turn seconds since epoch into timestamp with given format
        return datetime.fromtimestamp(decoded).strftime('%Y-%m-%dT%H:%M:%S')

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            #  parse string using given string, and return seconds since epoch
            #  as an int
            return int(datetime.strptime(string, '%Y-%m-%dT%H:%M:%S')
                       .timestamp())
        except ValueError as e:
            raise TypeError('Failed to parse date') from e

class Ether(AbstractLeaf, ABC):
    """
    leaf datatype class for ethernet addresses
    """
    def __init__(self, *args, **kwargs):
        super().__init__('ether')

    def encode(self, attribute, decoded):
        return struct.pack('!6B', *map(lambda x: int(x, 16), decoded.split(':')))

    def decode(self, raw, *args, **kwargs):
        #  return EUI object containing mac address
        return EUI(':'.join(map('{0:02x}'.format, struct.unpack('!6B', raw))))

    def print(self, attribute, decoded):
        return decoded

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError('Can not encode non-string as ethernet address')

        try:
            return EUI(string)
        except core.AddrFormatError as e:
            raise ValueError('Could not decode ethernet address') from e

class Float32(AbstractLeaf):
    """
    leaf datatype class for float32
    """

    def __init__(self, *args, **kwargs):
        super().__init__('float32')

    def encode(self, attribute, decoded):
        try:
            num = float(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-float as float32') from exc
        return struct.pack('!f', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!f', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = float(string)
        except ValueError as e:
            raise TypeError('Can not parse non-float as float32') from e
        else:
            return num

class Ifid(AbstractLeaf, ABC):
    """
    leaf datatype class for IFID (IPV6 interface ID)
    """
    def __init__(self, *args, **kwargs):
        super().__init__('ifid')

    def encode(self, attribute, decoded):
        struct.pack('!HHHH', *map(lambda x: int(x, 16), decoded.split(':')))

    def decode(self, raw, *args, **kwargs):
        ':'.join(map('{0:04x}'.format, struct.unpack('!HHHH', raw)))

    def print(self, attribute, decoded):
        # Following freeradius, IFIDs are displayed as a hex without any
        # delimiters
        return decoded.replace(':', '')

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        #  adds a : delimiter after every second character
        return ':'.join((string[i:i + 2] for i in range(0, len(string), 2)))

class Integer(AbstractLeaf):
    """
    leaf datatype class for integers
    """
    def __init__(self, *args, **kwargs):
        super().__init__('integer')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as integer') from exc
        return struct.pack('!I', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!I', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as int') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for int')
            if num > 4294967295:
                raise ValueError('Parsed value too large for int')
            return num

class Integer64(AbstractLeaf):
    """
    leaf datatype class for 64bit integers
    """
    def __init__(self, *args, **kwargs):
        super().__init__('integer64')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as 64bit integer') from exc
        return struct.pack('!Q', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!Q', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as int64') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for int64')
            if num > 18446744073709551615:
                raise ValueError('Parsed value too large for int64')
            return num

class Int64(AbstractLeaf):
    """
    leaf datatype class for int64
    """

    def __init__(self, *args, **kwargs):
        super().__init__('int64')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as int64') from exc
        return struct.pack('!q', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!q', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as int64') from e
        else:
            if num < -9223372036854775808:
                raise ValueError('Parsed value too small for int64')
            if num > 9223372036854775807:
                raise ValueError('Parsed value too large for int64')
            return num

class Ipaddr(AbstractLeaf):
    """
    leaf datatype class for ipv4 addresses
    """
    def __init__(self, *args, **kwargs):
        super().__init__('ipaddr')

    def encode(self, attribute, decoded):
        if not isinstance(decoded, str):
            raise TypeError('Address has to be a string')
        return IPv4Address(decoded).packed

    def decode(self, raw, *args, **kwargs):
        #  stored as strings, not ipaddress objects
        return '.'.join(map(str, struct.unpack('BBBB', raw)))

    def print(self, attribute, decoded):
        #  since object is already stored as a string, just return it as is
        return decoded

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            #  check if string is valid ipv4 address, but still returning the
            #  string representation
            return IPv4Address(string).exploded
        except AddressValueError as e:
            raise TypeError('Parsing invalid IPv4 address') from e

class Ipv4prefix(AbstractLeaf):
    """
    leaf datatype class for ipv4 addresses
    """
    def __init__(self, *args, **kwargs):
        super().__init__('ipv4prefix')

    def encode(self, attribute, decoded):
        prefix_length = decoded.prefixlen
        address = list(map(lambda x: int(x), decoded.network_address.exploded.split('.')))

        return struct.pack('!BBBBBB', *([0, prefix_length] + address))

    def decode(self, raw, *args, **kwargs):
        # decode the reserved, length, and prefix fields
        (_, prefix_length) = struct.unpack('!BB', raw[0:2])
        # decode the address
        address = '.'.join(map(lambda x: str(x) ,struct.unpack('!BBBB', raw[2:6])))
        return IPv4Network(f'{address}/{prefix_length}')

    def print(self, attribute, decoded):
        return decoded.exploded

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        return IPv4Network(string)

class Ipv6addr(AbstractLeaf):
    """
    leaf datatype class for ipv6 addresses
    """
    def __init__(self, *args, **kwargs):
        super().__init__('ipv6addr')

    def encode(self, attribute, decoded):
        if not isinstance(decoded, str):
            raise TypeError('IPv6 Address has to be a string')
        return IPv6Address(decoded).packed

    def decode(self, raw, *args, **kwargs):
        addr = raw + b'\x00' * (16 - len(raw))
        prefix = ':'.join(
            map(lambda x: f'{0:x}', struct.unpack('!' + 'H' * 8, addr))
        )
        return str(IPv6Address(prefix))

    def print(self, attribute, decoded):
        if not isinstance(decoded, str):
            raise TypeError(f'Parsing expects a string, got {type(decoded)}')

        try:
            #  check if valid address, but return string representation
            return IPv6Address(decoded).exploded
        except AddressValueError as e:
            raise TypeError('Parsing invalid IPv6 address') from e

    def parse(self, dictionary, string):
        return string

class Ipv6prefix(AbstractLeaf):
    """
    leaf datatype class for ipv6 prefixes
    """
    def __init__(self, *args, **kwargs):
        super().__init__('ipv6prefix')

    def encode(self, attribute, decoded):
        if not isinstance(decoded, str):
            raise TypeError('IPv6 Prefix has to be a string')
        ip = IPv6Network(decoded)
        return (struct.pack('2B', *[0, ip.prefixlen]) +
                ip.network_address.packed)

    def decode(self, raw, *args, **kwargs):
        addr = raw + b'\x00' * (18 - len(raw))
        _, length, prefix = ':'.join(
            map(lambda x: f'{0:x}' , struct.unpack('!BB' + 'H' * 8, addr))
        ).split(":", 2)
        #  returns string representation in the form of <Prefix>/<prefix len>
        return str(IPv6Network(f'{prefix}/{int(length, 16)}'))

    def print(self, attribute, decoded):
        #  we already store this value as a string, so just return it as is
        return decoded

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            return str(IPv6Network(string))
        except AddressValueError as e:
            raise TypeError('Parsing invalid IPv6 prefix') from e

class Octets(AbstractLeaf):
    """
    leaf datatype class for octets
    """
    def __init__(self, *args, **kwargs):
        super().__init__('octets')

    def encode(self, attribute, decoded):
        # Check for max length of the hex encoded with 0x prefix, as a sanity check
        if len(decoded) > 508:
            raise ValueError('Can only encode strings of <= 253 characters')

        if isinstance(decoded, bytes) and decoded.startswith(b'0x'):
            hexstring = decoded.split(b'0x')[1]
            encoded_octets = binascii.unhexlify(hexstring)
        elif isinstance(decoded, str) and decoded.startswith('0x'):
            hexstring = decoded.split('0x')[1]
            encoded_octets = binascii.unhexlify(hexstring)
        elif isinstance(decoded, str) and decoded.isdecimal():
            encoded_octets = struct.pack('>L', int(decoded)).lstrip(
                b'\x00')
        else:
            encoded_octets = decoded

        # Check for the encoded value being longer than 253 chars
        if len(encoded_octets) > 253:
            raise ValueError('Can only encode strings of <= 253 characters')

        return encoded_octets

    def decode(self, raw, *args, **kwargs):
        return raw

    def print(self, attribute, decoded):
        return decoded

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        return string

class Short(AbstractLeaf):
    """
    leaf datatype class for short integers
    """
    def __init__(self, *args, **kwargs):
        super().__init__('short')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as integer') from exc
        return struct.pack('!H', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!H', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as short') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for short')
            if num > 65535:
                raise ValueError('Parsed value too large for short')
            return num

class Signed(AbstractLeaf):
    """
    leaf datatype class for signed integers
    """
    def __init__(self, *args, **kwargs):
        super().__init__('signed')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as signed integer') from exc
        return struct.pack('!i', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!i', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as signed') from e
        else:
            if num < -2147483648:
                raise ValueError('Parsed value too small for signed')
            if num > 2147483647:
                raise ValueError('Parsed value too large for signed')
            return num

class String(AbstractLeaf):
    """
    leaf datatype class for strings
    """
    def __init__(self, *args, **kwargs):
        super().__init__('string')

    def encode(self, attribute, decoded):
        if len(decoded) > 253:
            raise ValueError('Can only encode strings of <= 253 characters')
        if isinstance(decoded, str):
            return decoded.encode('utf-8')
        return decoded

    def decode(self, raw, *args, **kwargs):
        return raw.decode('utf-8')

    def print(self, attribute, decoded):
        return decoded

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        return string

class Time(AbstractLeaf):
    """
    leaf datatype class for time (RFC8044)
    """

    def __init__(self, *args, **kwargs):
        super().__init__('time')

    def encode(self, attribute, decoded):
        if not isinstance(decoded, datetime):
            raise TypeError('Can not encode non datetime object as time')

        # take the seconds since epoch the timestamp represents, encode it as
        # an unsigned int, then return the encoding
        return struct.pack('!I', int(decoded.timestamp()))

    def decode(self, raw, *args, **kwargs):
        # return a datetime object with a timestamp using the number of seconds
        # since epoch as specified by the raw value
        return datetime.fromtimestamp(struct.unpack('!I', raw)[0])

    def print(self, attribute, decoded):
        if not isinstance(decoded, datetime):
            raise TypeError('Can not print non datetime object as time')
        return decoded.strftime('%Y-%m-%dT%H:%M:%S')

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            return datetime.strptime(string, '%Y-%m-%dT%H:%M:%S')
        except ValueError as e:
            raise TypeError('Failed to parse time') from e

class Timedelta(AbstractLeaf):
    """
    leaf datatype class for time_delta

    https://github.com/FreeRADIUS/freeradius-server/blob/10a2d7d172af0e3c275311b6fa7826789cc3a32b/src/lib/util/time.h#L80
    """
    def __init__(self, *args, **kwargs):
        self.precision = kwargs.get('precision')
        self.subtype = kwargs.get('subtype')

        super().__init__('time_delta')

    def encode(self, attribute: 'Attribute', decoded: any) -> bytes:
        if not isinstance(decoded, timedelta):
            raise TypeError('Can not encode non datetime object as time')

        # time_deltas are stored as an int, so encoding as such depending on
        # the subtype
        match self.subtype:
            case 'uint16':
                return struct.pack('!H', decoded)
            case 'int16':
                return struct.pack('!h', decoded)
            case 'uint32':
                return struct.pack('!I', decoded)
            case 'int32':
                return struct.pack('!i', decoded)
            case 'uint64':
                return struct.pack('!Q', decoded)
            # default case is signed int64
            case 'int64' | _:
                return struct.pack('!q', decoded)

    def decode(self, raw: bytes, *args, **kwargs) -> any:
        match self.subtype:
            case 'uint16':
                return struct.unpack('!H', raw)
            case 'int16':
                return struct.unpack('!h', raw)
            case 'uint32':
                return struct.unpack('!I', raw)
            case 'int32':
                return struct.unpack('!i', raw)
            case 'uint64':
                return struct.unpack('!Q', raw)
            # default case is signed int64
            case 'int64' | _:
                return struct.unpack('!q', raw)

    def print(self, attribute: 'Attribute', decoded: any) -> str:
        pass

    def parse(self, dictionary: 'Dictionary', string: str) -> any:
        pass

class Uint8(AbstractLeaf):
    """
    leaf datatype class for uint8
    """
    def __init__(self, *args, **kwargs):
        super().__init__('uint8')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as uint8') from exc
        return struct.pack('!B', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!B', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as uint8') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for uint8')
            if num > 255:
                raise ValueError('Parsed value too large for uint8')
            return num

class Uint16(AbstractLeaf):
    """
    leaf datatype class for uint16
    """

    def __init__(self, *args, **kwargs):
        super().__init__('uint16')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as uint16') from exc
        return struct.pack('!H', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!H', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as uint16') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for uint16')
            if num > 65535:
                raise ValueError('Parsed value too large for uint16')
            return num

class Uint32(AbstractLeaf):
    """
    leaf datatype class for uint32
    """

    def __init__(self, *args, **kwargs):
        super().__init__('uint32')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as uint32') from exc
        return struct.pack('!I', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!I', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as uint32') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for uint32')
            if num > 4294967295:
                raise ValueError('Parsed value too large for uint32')
            return num

class Uint64(AbstractLeaf):
    """
    leaf datatype class for uint64
    """

    def __init__(self, *args, **kwargs):
        super().__init__('uint64')

    def encode(self, attribute, decoded):
        try:
            num = int(decoded)
        except Exception as exc:
            raise TypeError('Can not encode non-integer as uint64') from exc
        return struct.pack('!Q', num)

    def decode(self, raw, *args, **kwargs):
        return struct.unpack('!Q', raw)[0]

    def print(self, attribute, decoded):
        return str(decoded)

    def parse(self, dictionary, string):
        if not isinstance(string, str):
            raise TypeError(f'Parsing expects a string, got {type(string)}')

        try:
            num = int(string)
        except ValueError as e:
            raise TypeError('Can not parse non-integer as uint64') from e
        else:
            if num < 0:
                raise ValueError('Parsed value too small for uint64')
            if num > 18446744073709551615:
                raise ValueError('Parsed value too large for uint64')
            return num
