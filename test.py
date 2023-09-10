#!/usr/bin/env python
"""
objscan unit tests
"""
import os
import unittest
from objscan import Scanner
from test import Helper as test

class ScannerLongTestCase(unittest.TestCase):
    TESTFILE_01 = "test/testfile_01"
    SHA1_TEST_01_TESTFILE_01 = "ec5ac62827f643178966f0c66d74b0834e6b93e0"
    sc = None

    def setUp(self):
        self.sc = Scanner(self.TESTFILE_01)

    def tearDown(self):
        os.remove(test.OUTPUT_FILE)

    def test01_slab_1024(self):
        self.sc.get_obj_for_size(1024, False, test.OUTPUT_FILE)
        self.assertEqual(test.sha1_from_file(test.OUTPUT_FILE), 
                         self.SHA1_TEST_01_TESTFILE_01)

class ScannerQuickTestCase(unittest.TestCase):
    TESTFILE_02 = "test/testfile_02"
    SHA1_TEST_02_TESTFILE_02 = "bac1acb0bb24756502d3e7a50b29751947230a21"
    SHA1_TEST_03_TESTFILE_02 = "ba89172575734b2c1f06d186883614ee0d18689a"
    sc = None

    def setUp(self):
        self.sc = Scanner(self.TESTFILE_02)

    def tearDown(self):
        os.remove(test.OUTPUT_FILE)

    def test02_slab_96_elastic(self):
        self.sc.get_obj_for_size(96, True, test.OUTPUT_FILE)
        self.assertEqual(test.sha1_from_file(test.OUTPUT_FILE), 
                         self.SHA1_TEST_02_TESTFILE_02)

    def test03_slab_1024_elastic(self):
        self.sc.get_obj_for_size(1024, True, test.OUTPUT_FILE)
        self.assertEqual(test.sha1_from_file(test.OUTPUT_FILE), 
                         self.SHA1_TEST_03_TESTFILE_02)


class ScannerElasticTestCase(unittest.TestCase):
    TESTFILE_03 = "test/testfile_03"
    SHA1_TEST_04_TESTFILE_03 = "1aa86861c4f9022bd2bffc883f8243730640ab38"
    sc = None

    def setUp(self):
        self.sc = Scanner(self.TESTFILE_03)

    def tearDown(self):
        os.remove(test.OUTPUT_FILE)

    def test04_slab_1024_elastic(self):
        self.sc.get_obj_for_size(1024, True, test.OUTPUT_FILE)
        self.assertEqual(test.sha1_from_file(test.OUTPUT_FILE), 
                         self.SHA1_TEST_04_TESTFILE_03)

def suite():
    suite = unittest.TestSuite()
    suite.addTest(ScannerLongTestCase('test01_slab_1024'))
    suite.addTest(ScannerQuickTestCase('test02_slab_96_elastic'))
    suite.addTest(ScannerQuickTestCase('test03_slab_1024_elastic'))
    suite.addTest(ScannerElasticTestCase('test04_slab_1024_elastic'))
    return suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suite())
