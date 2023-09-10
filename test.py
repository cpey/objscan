#!/usr/bin/env python
"""
objscan unit tests
"""
import os
import unittest
from objscan import Scanner
from test import Helper as UT

class ScannerLongTestCase(unittest.TestCase):
    TESTFILE_01 = "test/testfile_01"
    SHA1_TEST_01_TESTFILE_01 = "ec5ac62827f643178966f0c66d74b0834e6b93e0"
    sc = None

    def setUp(self):
        self.sc = Scanner(self.TESTFILE_01, UT.ONE_JOB, False)

    def tearDown(self):
        os.remove(UT.OUTPUT_FILE)

    def test01_slab_1024(self):
        self.sc.get_objs_for_size(1024, False, UT.OUTPUT_FILE)
        self.assertEqual(UT.sha1_from_file(UT.OUTPUT_FILE),
                         self.SHA1_TEST_01_TESTFILE_01)

class ScannerQuickTestCase(unittest.TestCase):
    TESTFILE_02 = "test/testfile_02"
    SHA1_TEST_02_TESTFILE_02 = "bac1acb0bb24756502d3e7a50b29751947230a21"
    SHA1_TEST_03_TESTFILE_02 = "ba89172575734b2c1f06d186883614ee0d18689a"

    def setUp(self):
        self.sc = Scanner(self.TESTFILE_02, UT.ONE_JOB, False)

    def tearDown(self):
        os.remove(UT.OUTPUT_FILE)

    def test02_slab_96_elastic(self):
        self.sc.get_objs_for_size(96, True, UT.OUTPUT_FILE)
        self.assertEqual(UT.sha1_from_file(UT.OUTPUT_FILE),
                         self.SHA1_TEST_02_TESTFILE_02)

    def test03_slab_1024_elastic(self):
        self.sc.get_objs_for_size(1024, True, UT.OUTPUT_FILE)
        self.assertEqual(UT.sha1_from_file(UT.OUTPUT_FILE),
                         self.SHA1_TEST_03_TESTFILE_02)

class ScannerElasticTestCase(unittest.TestCase):
    TESTFILE_03 = "test/testfile_03"
    SHA1_TEST_04_TESTFILE_03 = "1aa86861c4f9022bd2bffc883f8243730640ab38"

    def setUp(self):
        self.sc = Scanner(self.TESTFILE_03, UT.ONE_JOB, False)

    def tearDown(self):
        os.remove(UT.OUTPUT_FILE)

    def test04_slab_1024_elastic(self):
        self.sc.get_objs_for_size(1024, True, UT.OUTPUT_FILE)
        self.assertEqual(UT.sha1_from_file(UT.OUTPUT_FILE), 
                         self.SHA1_TEST_04_TESTFILE_03)

class ScannerJobsTestCase(unittest.TestCase):
    TESTFILE_01 = "test/testfile_01"
    OUTPUT_FILE_AS_REFERENCE = "test/output_size_1024_testfile_01"

    def setUp(self):
        self.sc = Scanner(self.TESTFILE_01, UT.FOUR_JOBS, False)

    def tearDown(self):
        pass#os.remove(UT.OUTPUT_FILE)

    def test05_slab_1024_jobs_4(self):
        self.sc.get_objs_for_size(1024, False, UT.OUTPUT_FILE)
        result = UT.load_file(UT.OUTPUT_FILE)
        reference = UT.load_file(self.OUTPUT_FILE_AS_REFERENCE)
        for item in result:
            if item in reference:
               reference.remove(item)
        self.assertEqual(len(reference), 0)

def suite():
    suite = unittest.TestSuite()
    suite.addTest(ScannerLongTestCase('test01_slab_1024'))
    suite.addTest(ScannerQuickTestCase('test02_slab_96_elastic'))
    suite.addTest(ScannerQuickTestCase('test03_slab_1024_elastic'))
    suite.addTest(ScannerElasticTestCase('test04_slab_1024_elastic'))
    suite.addTest(ScannerJobsTestCase('test05_slab_1024_jobs_4'))
    return suite

if __name__ == '__main__':
    runner = unittest.TextTestRunner()
    runner.run(suite())
