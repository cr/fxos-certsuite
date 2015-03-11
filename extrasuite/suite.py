# -*- encoding: utf-8 -*-

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import logging
import argparse
import traceback
from mozdevice import DeviceManagerADB, DMError, ADBError
from mozlog.structured import commandline
from time import sleep


class ExtraTest( object ):
	
	@classmethod
	def groupname( cls ):
		if cls.group:
			return cls.group
		else:
			 return "unknown"

	@staticmethod
	def group_list():
		groups = []
		for t in ExtraTest.__subclasses__():
			if t.groupname() not in groups:
				groups.append( t.groupname() )
		return groups

	@staticmethod
	def test_list( group=None ):
		if group is None:
			return ExtraTest.__subclasses__()
		else:
			tests = []
			for t in ExtraTest.__subclasses__():
				if t.groupname() == group:
					tests.append( t )
			return tests

	@classmethod
	def run( cls, group=None ):
		for t in cls.test_list( group ):
			t.run()


def wait_for_adb_device():
	try:
		adb = DeviceManagerADB()
	except DMError:
		adb = None
		print "Waiting for adb connection..."
	while adb is None:
		try:
			adb = DeviceManagerADB()
		except DMError:
			sleep( 0.2 )
	if len( adb.devices() ) < 1:
		print "Waiting for adb device..."
		while len( adb.devices() ) < 1:
			sleep( 0.2 )

def adb_has_root():
	# normally this should check via root=True to .shellCheckOutput, but doesn't work
	adb = DeviceManagerADB()
	return adb.shellCheckOutput( ["id"] ).startswith( "uid=0(root)" )

def extracli():
    parser = argparse.ArgumentParser( description="Runner for extra test suite")
    parser.add_argument("-l", "--list-test-groups", action="store_true",
                        help="List all logical test groups")
    parser.add_argument("-a", "--list-all-tests", action="store_true",
                        help="List all tests")
    parser.add_argument("-i", "--include", metavar="GROUP", action="append", default=[],
                        help="Only include specified group(s) in run, include several "
                        "groups by repeating flag")
    parser.add_argument("--version", action="store", dest="version",
                        help="B2G version")
    parser.add_argument("--ipython", dest="ipython", action="store_true",
                        help="drop to ipython session")  
    parser.add_argument("-v", dest="verbose", action="store_true",
                        help="Verbose output")  
    commandline.add_logging_group(parser)
    args = parser.parse_args()
    logger = commandline.setup_logging("extrasuite", vars(args), {"raw": sys.stdout})

    try:
        logger.debug( "extra cli runnng with args %s" % args )
        if args.list_test_groups:
            for group in ExtraTest.group_list():
                print group
        elif args.list_all_tests:
            for test in ExtraTest.test_list():
                print "%s.%s" % (test.group, test.__name__)
        elif args.ipython:
            from IPython import embed
            embed()
        else:
            wait_for_adb_device()
            if not adb_has_root():
                print "WARNING: adb has no root. Results will be incomplete."
            if len( args.include ) == 0: # run all groups
                for t in ExtraTest.test_list():
                    print "running %s" % t
                    t.run()
            else:                        # run only included groups
                for g in args.include:
                    for t in ExtraTest.test_list( g ):
                        print "running %s" % t
                        t.run()
			
    except:
        logger.critical(traceback.format_exc())
        raise

if __name__ == "__main__":
    extracli()
