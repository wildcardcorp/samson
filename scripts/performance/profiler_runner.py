#!/usr/bin/python3
# Based off of https://github.com/GoogleCloudPlatform/python-docs-samples/blob/master/appengine/standard/localtesting/runner.py
import unittest
import os
import argparse

def main(test_path, test_pattern):
    suite = unittest.loader.TestLoader().discover(test_path, test_pattern)
    return unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '--test-path',
        help='The path to look for tests, defaults to the current directory.',
        default=os.getcwd())
    parser.add_argument(
        '--test-pattern',
        help='The file pattern for test modules, defaults to test_*.py.',
        default='test_*.py')

    args = parser.parse_args()

    main(args.test_path, args.test_pattern)