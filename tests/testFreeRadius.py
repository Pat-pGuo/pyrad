import unittest
import os

from pyrad.packet import Packet
from tests.frparser.parser import V4TestCaseParser, TestTypes
from pyrad.dictionary import Dictionary

class TestFreeRadius(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.parser = V4TestCaseParser(None)
        cls.dictionary = Dictionary(dict='')
        cls.packet = Packet(dict=cls.dictionary)

    def setUp(self):
        self.previous = None

    def testProtocols(self):
        for root, dirs, files in os.walk('./protocols'):
            for file in files:
                with self.subTest(file=file):
                    testcases = self.parser.parse(os.path.join(root, file),
                                                  self.dictionary)
                    for ttype, values in testcases:
                        self.previous = []
                        match ttype:
                            case TestTypes.encode:
                                for value in values:
                                    attribute = self.dictionary[list(value.keys())[0]]
                                    self.previous.append(attribute.type.encode(value))
                            case TestTypes.decode:
                                self.previous = self.packet.DecodeAttributes(value)
                            case TestTypes.match_bytes:
                                self.assertEqual(self.previous,
                                                 self.packet.DecodeAttributes(value))
                            case TestTypes.match_vps:
                                vps = []
                                for value in values:
                                    attribute = self.dictionary[list(value.keys())[0]]
                                    vps.append(attribute.type.encode(value))
                                self.assertEqual(self.previous, vps)
                            case _:
                                #  raises exception if unknown test types is
                                #  passed in
                                raise Exception
