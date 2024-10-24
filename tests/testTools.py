import struct
from ipaddress import AddressValueError
from pyrad import tools
import unittest


class EncodingTests(unittest.TestCase):
    def testStringEncoding(self):
        self.assertRaises(ValueError, tools.EncodeString, 'x' * 254)
        self.assertEqual(
                tools.EncodeString('1234567890'),
                b'1234567890')

    def testInvalidStringEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeString, 1)

    def testAddressEncoding(self):
        self.assertRaises(AddressValueError, tools.EncodeAddress, 'TEST123')
        self.assertEqual(
                tools.EncodeAddress('192.168.0.255'),
                b'\xc0\xa8\x00\xff')

    def testInvalidAddressEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeAddress, 1)

    def testIntegerEncoding(self):
        self.assertEqual(tools.EncodeInteger(0x01020304), b'\x01\x02\x03\x04')

    def testInteger64Encoding(self):
        self.assertEqual(
            tools.EncodeInteger64(0xFFFFFFFFFFFFFFFF), b'\xff' * 8
        )

    def testUnsignedIntegerEncoding(self):
        self.assertEqual(tools.EncodeInteger(0xFFFFFFFF), b'\xff\xff\xff\xff')

    def testInvalidIntegerEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeInteger, 'ONE')

    def testDateEncoding(self):
        self.assertEqual(tools.EncodeDate(0x01020304), b'\x01\x02\x03\x04')

    def testInvalidDataEncodingRaisesTypeError(self):
        self.assertRaises(TypeError, tools.EncodeDate, '1')

    def testEncodeAscendBinary(self):
        self.assertEqual(
            tools.EncodeAscendBinary('family=ipv4 action=discard direction=in dst=10.10.255.254/32'),
            b'\x01\x00\x01\x00\x00\x00\x00\x00\n\n\xff\xfe\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    def testStringDecoding(self):
        self.assertEqual(
                tools.DecodeString(b'1234567890'),
                '1234567890')

    def testAddressDecoding(self):
        self.assertEqual(
                tools.DecodeAddress(b'\xc0\xa8\x00\xff'),
                '192.168.0.255')

    def testIntegerDecoding(self):
        self.assertEqual(
                tools.DecodeInteger(b'\x01\x02\x03\x04'),
                0x01020304)

    def testInteger64Decoding(self):
        self.assertEqual(
            tools.DecodeInteger64(b'\xff' * 8), 0xFFFFFFFFFFFFFFFF
        )

    def testDateDecoding(self):
        self.assertEqual(
                tools.DecodeDate(b'\x01\x02\x03\x04'),
                0x01020304)

    def testOctetsEncoding(self):
        self.assertEqual(tools.EncodeOctets('0x01020304'), b'\x01\x02\x03\x04')
        self.assertEqual(tools.EncodeOctets(b'0x01020304'), b'\x01\x02\x03\x04')
        self.assertEqual(tools.EncodeOctets('16909060'), b'\x01\x02\x03\x04')
        # encodes to 253 bytes
        self.assertEqual(tools.EncodeOctets('0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D'), b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r')
        self.assertRaisesRegex(ValueError, 'Can only encode strings of <= 253 characters', tools.EncodeOctets, '0x0102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E0F100102030405060708090A0B0C0D0E')

    def testUnknownTypeEncoding(self):
        self.assertRaises(ValueError, tools.EncodeAttr, 'unknown', None)

    def testUnknownTypeDecoding(self):
        self.assertRaises(ValueError, tools.DecodeAttr, 'unknown', None)

    def testComboIpEncoding(self):
        self.assertEqual(tools.EncodeComboIp('1.2.3.4'), b'\x01\x02\x03\x04')
        self.assertEqual(tools.EncodeComboIp('0102:0304:0506:0708:090A:0B0C:0D0E:0F10'), b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10')
        self.assertEqual(tools.EncodeComboIp('0102::0304'), b'\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x04')

        self.assertRaises(ValueError, tools.EncodeComboIp, '1.2.3')
        self.assertRaises(ValueError, tools.EncodeComboIp, '0102:0304:0506:0708:090A:0B0C:0D0E')

    def testComboIpDecoding(self):
        self.assertEqual(tools.DecodeComboIp(b'\x01\x02\x03\x04'), '1.2.3.4')
        self.assertEqual(tools.DecodeComboIp(b'\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10'), '102:304:506:708:90a:b0c:d0e:f10')
        self.assertEqual(tools.DecodeComboIp(b'\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x04'), '102::304')

        self.assertRaises(struct.error, tools.DecodeComboIp, b'\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x04\00')

    def testBoolEncoding(self):
        self.assertEqual(tools.EncodeBool(1), b'\x01')
        self.assertEqual(tools.EncodeBool(True), b'\x01')
        self.assertEqual(tools.EncodeBool(0), b'\x00')
        self.assertEqual(tools.EncodeBool(False), b'\x00')

        self.assertRaises(TypeError, tools.EncodeBool, None)

    def testBoolDecoding(self):
        self.assertEqual(tools.DecodeBool(b'\x01'), True)
        self.assertEqual(tools.DecodeBool(b'\x02'), True)
        self.assertEqual(tools.DecodeBool(b'\x00'), False)

        self.assertRaises(TypeError, tools.DecodeBool, None)
        self.assertRaises(struct.error, tools.DecodeBool, b'\x00\x01')

    def testIfidEncoding(self):
        self.assertEqual(tools.EncodeIfid('1011:1213:1415:1617'), b'\x10\x11\x12\x13\x14\x15\x16\x17')

        self.assertRaises(struct.error, tools.EncodeIfid, '1011')

    def testIfidDecoding(self):
        self.assertEqual(tools.DecodeIfid(b'\x10\x11\x12\x13\x14\x15\x16\x17'), '1011:1213:1415:1617')

        self.assertRaises(struct.error, tools.DecodeIfid, b'')
        self.assertRaises(struct.error, tools.DecodeIfid, b'\x10\x11\x12\x13\x14\x15\x16\x17\x18')

    def testEtherEncoding(self):
        self.assertEqual(tools.EncodeEther('11:12:13:14:15:16'), b'\x11\x12\x13\x14\x15\x16')

        self.assertRaises(struct.error, tools.EncodeEther, '11:12:13:14:15')
        self.assertRaises(struct.error, tools.EncodeEther, '11:12:13:14:15:16:17')

    def testEtherDecoding(self):
        self.assertEqual(tools.DecodeEther(b'\x11\x12\x13\x14\x15\x16'), '11:12:13:14:15:16')

        self.assertRaises(struct.error, tools.DecodeEther, b'\x11\x12\x13\x14\x15\x16\17')
        self.assertRaises(struct.error, tools.DecodeEther, b'\x11\x12\x13\x14\x15')

    def testEncodeFunction(self):
        self.assertEqual(
                tools.EncodeAttr('string', 'string'),
                b'string')
        self.assertEqual(
                tools.EncodeAttr('octets', b'string'),
                b'string')
        self.assertEqual(
                tools.EncodeAttr('ipaddr', '192.168.0.255'),
                b'\xc0\xa8\x00\xff')
        self.assertEqual(
                tools.EncodeAttr('integer', 0x01020304),
                b'\x01\x02\x03\x04')
        self.assertEqual(
                tools.EncodeAttr('date', 0x01020304),
                b'\x01\x02\x03\x04')
        self.assertEqual(
                tools.EncodeAttr('integer64', 0xFFFFFFFFFFFFFFFF),
                b'\xff'*8)

    def testDecodeFunction(self):
        self.assertEqual(
                tools.DecodeAttr('string', b'string'),
                'string')
        self.assertEqual(
                tools.EncodeAttr('octets', b'string'),
                b'string')
        self.assertEqual(
                tools.DecodeAttr('ipaddr', b'\xc0\xa8\x00\xff'),
                '192.168.0.255')
        self.assertEqual(
                tools.DecodeAttr('integer', b'\x01\x02\x03\x04'),
                0x01020304)
        self.assertEqual(
                tools.DecodeAttr('integer64', b'\xff'*8),
                0xFFFFFFFFFFFFFFFF)
        self.assertEqual(
                tools.DecodeAttr('date', b'\x01\x02\x03\x04'),
                0x01020304)
