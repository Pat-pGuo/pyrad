from pyrad.dictionary import Dictionary
import enum

class TestTypes(enum.Enum):
    encode: 1
    decode: 2
    match_bytes: 3
    match_vps: 4

class V4TestCaseParser:
    def __init__(self, dictionary):
        self.dictionary: Dictionary = dictionary

        self.handlers = {
            'encode-pair': self.encode_pair,
            'decode-pair': self.decode_pair,
            'match': self.match,
        }

    def parse(self, file, dictionary):
        self.dictionary = dictionary

        testcases = []

        with open(file, 'r') as fileopen:
            for line in fileopen:
                for key, handler in self.handlers:
                    if line.startswith(key):
                        testcases.append(handler(line))

        return testcases

    def __get_vps(self, buffer):
        vps = []

        # if given multiple vps, split them by their delimiter, commas
        raws = buffer.split(', ')
        for raw in raws:
            # take the buffer, split it by spaces, and the first index is the
            # attribute name. Then, we index the dictionary by the name to get
            # the attribute object itself
            attribute = self.dictionary[raw.split(' ')[0]]

            # using the attribute's datatype's parse function, get the python
            # representation of the object
            vps.append(attribute.type.parse(raw))

        return vps

    def encode_pair(self, buffer):
        # skip over the "encode-pair " prefix when getting the vps
        return TestTypes.encode, self.__get_vps(buffer[12:])

    def decode_pair(self, buffer):
        # skip over the "decode-pair" and start at the hex string
        # first, convert hex into bytes
        return TestTypes.decode, bytes.fromhex(buffer[12:])

    def match(self, buffer):
        # we need to figure out if we are matching against a hexstring or a
        # value pair
        try:
            # we first try to treat it as a hexstring
            # skip over the "match " prefix in the buffer string
            return TestTypes.match_bytes, bytes.fromhex(buffer[6:])
        except ValueError:
            # if above fails, then we treat it as a value pair
            return TestTypes.match_vps, self.__get_vps(buffer[6:])
