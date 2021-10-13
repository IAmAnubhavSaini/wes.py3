#!/usr/bin/env python3

import argparse
import csv
import datetime
import io
import os
import platform
import re
import urllib.error
import urllib.request
from io import StringIO
from sys import exit
from tempfile import NamedTemporaryFile

# constants/globals
MSSB_URL = 'http://www.microsoft.com/en-gb/download/confirmation.aspx?id=36982'
BULLETIN_URL = 'http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx'
VERSION = "3.3"

# global parser
parser = argparse.ArgumentParser(
    description="search microsoft security bulletins for exploits based upon the patch level of the machine by feeding in systeminfo command")
parser.add_argument("-v", "--verbose", help="verbose output", action="store_true")
parser.add_argument("-i", "--systeminfo", help="feed in an input file that contains the 'systeminfo' command")
parser.add_argument("-d", "--database", help="the file that contains the microsoft security bulletin database")
parser.add_argument("-u", "--update", help="required flag to even run the script", action="store_true")
parser.add_argument("-a", "--audit", help="show all entries, not only exploits", action="store_true")
parser.add_argument("-t", "--trace", help="used to determine linked ms bulletins")
parser.add_argument("-p", "--patches", help="used to determine specific patches for a ms bulletin")
parser.add_argument("-o", "--ostext",
                    help="a loose text representation of the windows OS (ex: \"windows xp home edition sp2\")")
parser.add_argument("-s", "--sub", help="generate output using linked/sub bulletins. WARNING: SLOW!",
                    action="store_true")
parser.add_argument("-2", "--duplicates",
                    help="allow duplicate ms bulletin output within the results. this will produce a lot of output, but is useful when determining linked ms bulletins",
                    action="store_true")
parser.add_argument("-q", "--quiet", help="don't show exploit information. shorter output", action="store_true")
# hotfixes
# used to parse "wmic qfe list full" input, and to solve the 'File 1' errors
parser.add_argument("-H", "--hotfixes",
                    help="a loose list of hotfixes to be added, for use with the following command: 'wmic qfe list full'")

# search by exploit type only
exptypegroup = parser.add_mutually_exclusive_group()
exptypegroup.add_argument("-r", "--remote", help="search remote exploits only", action="store_true")
exptypegroup.add_argument("-l", "--local", help="search local exploits only", action="store_true")

# global args parsed
ARGS = parser.parse_args()


def main():
    ALERT("initiating winsploit version %s..." % VERSION)

    database = ''

    # if there is a database switch
    if ARGS.database:

        # split name and extension
        name, extension = os.path.splitext(ARGS.database)

        # csv code has been removed.
        # only xls
        if 'xls' in extension:
            ALERT("Database file detected as xls based on extension", ALERT.NORMAL)

            try:
                import xlrd
            except ImportError:
                import xlrd  # should be try and except
                ALERT("please install and upgrade the python-xlrd library", ALERT.BAD)
                exit(1)

            # open the xls file
            try:
                wb = xlrd.open_workbook(ARGS.database)
            except IOError as e:
                ALERT(
                    "no such file or directory '%s'. ensure you have the correct database file passed in --database/-d" % ARGS.database,
                    ALERT.BAD)
                exit(1)

            sh = wb.sheet_by_index(0)

            # read the spreadsheet into a temp file
            f = NamedTemporaryFile(mode='wb')
            data = ''

            # loop through xls
            for rownum in range(sh.nrows):

                values = sh.row_values(rownum)

                # loop through row values, and process input
                for i in range(len(values)):
                    values[i] = str(values[i])
                    values[i] = values[i].replace('\n', ' ')
                    values[i] = values[i].replace(',', '')
                    values[i] = values[i].replace('.0', '')

                data += ",".join(values)
                data += '\n'

            # set the database to the csv data
            database = data

        # unknown filetype, error
        else:
            ALERT("unknown filetype. Use .xls", ALERT.BAD)
            exit(1)

    if ARGS.trace:
        trace(database)
    elif ARGS.systeminfo or ARGS.ostext:
        run(database)
    elif ARGS.update:
        update()
    elif ARGS.patches:
        patches(database)

    # error
    else:
        ALERT("an error occurred while running, not enough arguments", ALERT.BAD)
        exit(1)

    ALERT("done")
    # end main()


def run(database):
    # variables used
    ostext = None
    name = None
    release = None
    servicepack = None

    # will default to 32-bit, but can be 64 bit or itanium
    architecture = None

    hotfixes = set([])
    bulletinids = set([])

    potential = []

    vulns = {}
    ids = set([])

    cmdoutput = []

    # test for database
    if not ARGS.database:
        ALERT(
            "please supply a MSSB database file with the --database or -d flag, this can be downloaded using the --update command",
            ALERT.BAD)
        exit(1)

    # read from ostext first
    if ARGS.ostext:
        ALERT("getting OS information from command line text")

        name = getname(ARGS.ostext)
        release = getrelease(ARGS.ostext)
        servicepack = getservicepack(ARGS.ostext)
        architecture = getarchitecture(ARGS.ostext)

        # the os name at least has to be identified
        if not name:
            ALERT("unable to determine the windows version command line text from '%s'" % ARGS.ostext, ALERT.BAD)
            exit(1)

    # get the systeminfo information from the input file
    if ARGS.systeminfo:

        ALERT("attempting to read from the systeminfo input file")

        # when reading the systeminfo file, we want to attempt to detect it using chardet
        # if this doesn't work, we will loop through a list of common encodings and try them all
        encodings = ['utf-8', 'utf-16', 'utf-16-le', 'utf-16-be', 'iso-8859-2']

        detected_encoding = detect_encoding(ARGS.systeminfo)

        # insert detected encoding to the front of the list
        if detected_encoding:
            if ARGS.verbose: ALERT("detected encoding of file as '%s'" % detected_encoding)
            encodings.insert(0, detected_encoding)

        cmdfile = None
        cmdoutput = None

        # now loop through all encodings, with the detected one first (if it was possible)
        for encoding in encodings:

            if ARGS.verbose: ALERT("  attempting to read with '%s' encoding" % encoding)

            # if we can read the file, and read the command output, we are done with the loop
            try:
                cmdfile = io.open(ARGS.systeminfo, "r", encoding=encoding)  # throws UnicodeDecodeError
                cmdoutput = cmdfile.readlines()  # throws UnicodeError
                break

            except (UnicodeError, UnicodeDecodeError) as e:
                ALERT("could not read file using '%s' encoding: %s" % (encoding, e), ALERT.BAD)

            # file might not exist
            except:
                ALERT("could not read from input file specified: %s" % ARGS.systeminfo, ALERT.BAD)
                exit(1)

        # general catchall if somehow it was able to keep processing
        if not cmdfile or not cmdoutput:
            ALERT("could not read from input file, or could not detect encoding", ALERT.BAD)
            exit(1)

        # file read successfully
        ALERT("systeminfo input file read successfully (%s)" % encoding, ALERT.GOOD)

    # error
    if not ARGS.systeminfo and not ARGS.ostext and platform.system() != 'Windows':
        ALERT(
            "please run from a Windows machine, or provide an input file using --systeminfo, or use the --ostext option to get data with no patch information",
            ALERT.BAD)
        exit(1)

    # parse the systeminfo information
    hotfix = False

    # loop through the systeminfo input
    for haystack in cmdoutput:

        # only attempt to set the version, arch, service pack if there is no
        # ostext flag
        if not ARGS.ostext:

            # when detecting the operating system version, every line (independent of language)
            # appears to have Microsoft Windows in it, sometimes with (R)
            if "Microsoft" in haystack and "Windows" in haystack and not name:
                name = getname(haystack)

            # the windows release is similar to the above and has the text 'Microsoft Windows' in the text
            if "Microsoft" in haystack and "Windows" in haystack and not release:
                release = getrelease(haystack)

            # similar to OS, there is the words 'Service Pack'
            if "Service Pack" in haystack and not servicepack:
                servicepack = getservicepack(haystack)

            # get architecture only if -based is in the line, and --ostext hasn't been used
            if "-based" in haystack and not architecture:
                architecture = getarchitecture(haystack)

        # look for kbs
        if ("KB" in haystack or "]: " in haystack):
            patch = getpatch(haystack)

            # if a patch was parsed
            if patch:
                if ARGS.verbose: ALERT("found hotfix %s" % patch)
                hotfixes.add(patch)

    # now process the hotfixes argument input
    if ARGS.hotfixes:

        encodings = ['utf-8', 'utf-16', 'utf-16-le', 'utf-16-be', 'iso-8859-2']

        detected_encoding = detect_encoding(ARGS.systeminfo)

        # insert detected encoding to the front of the list
        if detected_encoding:
            if ARGS.verbose: ALERT("detected encoding of file as '%s'" % detected_encoding)
            encodings.insert(0, detected_encoding)

        cmdfile = None
        hotfixesfile = None

        # now loop through all encodings, with the detected one first (if it was possible)
        for encoding in encodings:

            if ARGS.verbose: ALERT("  attempting to read with '%s' encoding" % encoding)

            # if we can read the file, and read the command output, we are done with the loop
            try:
                cmdfile = io.open(ARGS.hotfixes, "r", encoding=encoding)  # throws UnicodeDecodeError
                hotfixesfile = cmdfile.readlines()  # throws UnicodeError
                break

            except (UnicodeError, UnicodeDecodeError) as e:
                if ARGS.verbose: ALERT("could not read file using '%s' encoding: %s" % (encoding, e), ALERT.BAD)

            # file might not exist
            except:
                ALERT("could not read from input file specified: %s" % ARGS.hotfixes, ALERT.BAD)
                exit(1)

        # general catchall if somehow it was able to keep processing
        if not cmdfile or not hotfixesfile:
            ALERT("could not read from input file, or could not detect encoding", ALERT.BAD)
            exit(1)

        # file read successfully
        ALERT("hotfixes input file read successfully (%s)" % encoding, ALERT.GOOD)

        # loop through hotfixes file input
        for haystack in hotfixesfile:
            # look for kbs
            if ("KB" in haystack or "]: " in haystack):
                patch = getpatch(haystack)

                # if a patch was parsed
                if patch:
                    if ARGS.verbose: ALERT("found hotfix %s" % patch)
                    hotfixes.add(patch)

    if ARGS.verbose:
        ALERT("name: %s; release: %s; servicepack: %s; architecture: %s" % (name, release, servicepack, architecture))

    # verify that a windows os was at least able to be parsed
    if not name:
        if ARGS.systeminfo:
            ALERT(
                "unable to determine the windows versions from the input file specified. consider using --ostext option to force detection (example: --ostext 'windows 7 sp1 64-bit')",
                ALERT.BAD)
            exit(1)

    if ARGS.verbose:
        ALERT("name: %s" % name)
        ALERT("release: %s" % release)
        ALERT("service pack: %s" % servicepack)
        ALERT("architecture: %s" % architecture)

    ALERT("querying database file for potential vulnerabilities")

    # potential, all matches within the CSV database for the name,release,sp,arch
    # bulletinds, set of the above with MSIDs (good to keep count)

    # get the potential bulletins
    try:
        for row in csv.reader(StringIO(database)):
            bulletinid = row[1]
            affected = row[6]

            if isaffected(name, release, servicepack, architecture, affected):

                # only add the bulletin if it's not already in the list
                if bulletinid not in bulletinids:
                    potential.append(row)
                    bulletinids.add(bulletinid)

                    if ARGS.verbose:
                        ALERT("%s has been added to potential list '%s'" % (bulletinid, affected))

    except csv.Error:
        ALERT('could not parse database file, make sure it is in the proper format', ALERT.BAD)
        exit(1)

    # there should always be some potential vulns, because of the amount of windows software and false positives
    if len(bulletinid) == 0:
        ALERT("there are no potential vulnerabilities for, ensure you're searching a valid windows OS", ALERT.BAD)
        exit(1)

    ALERT("comparing the %s hotfix(es) against the %s potential bulletins(s) with a database of %s known exploits" % (
        len(hotfixes), len(bulletinids), getexploit()))

    # start removing the vulns because of hotfixes
    for row in list(potential):

        # ms bulletin
        bulletinid = row[1]
        kb = row[2]
        componentkb = row[7]

        for hotfix in hotfixes:

            # if either the hotfixes match the kb or componentkb columns, and the bulletin is in the list
            # of potential bulletins
            if (hotfix == kb or hotfix == componentkb) and bulletinid in bulletinids:

                if ARGS.verbose:
                    ALERT("  %s hotfix triggered a removal of %skb and the %s bulletin; componentkb is %s" % (
                        hotfix, kb, bulletinid, componentkb))

                # get the linked ms, this will automatically calculate the superseded by as well
                linkedms = get_linked_ms([bulletinid], csv.reader(StringIO(database)))
                linkedmsstr = ''

                # calculate the pretty string, only care when verbose
                if len(linkedms) > 0:
                    for m in linkedms:
                        linkedmsstr += ' ' + m

                if ARGS.verbose:

                    if hotfix == kb:
                        ALERT("    due to presence of KB%s (Bulletin KB) removing%s bulletin(s)" % (kb, linkedmsstr))

                    elif componentkb == kb:
                        ALERT("    due to presence of KB%s (Component KB) removing%s bulletin(s)" % (
                            componentkb, linkedmsstr))

                bulletinids = bulletinids.difference(linkedms)
                potential.remove(row)

    ALERT("there are now %s remaining vulns" % len(bulletinids))

    # search local exploits only
    if ARGS.local:
        ALERT("searching for local exploits only")
        for row in list(potential):
            bulletinid = row[1]
            impact = row[4]

            if bulletinid in bulletinids and not "elevation of privilege" in impact.lower():

                remove = get_linked_ms([bulletinid], csv.reader(StringIO(database)))

                if ARGS.verbose:
                    ALERT("   removing %s (total of %s MS ids), because of its impact %s" % (
                        bulletinid, len(remove), impact))

                bulletinids = bulletinids.difference(remove)
                potential.remove(row)

    # search remote exploits only
    if ARGS.remote:
        ALERT("searching for remote exploits only")
        for row in list(potential):
            bulletinid = row[1]
            impact = row[4]

            if bulletinid in bulletinids and not "remote code execution" in impact.lower():

                remove = get_linked_ms([bulletinid], csv.reader(StringIO(database)))

                if ARGS.verbose:
                    ALERT("   removing %s (total of %s MS ids), because of its impact %s" % (
                        bulletinid, len(remove), impact))

                bulletinids = bulletinids.difference(remove)
                potential.remove(row)

    # print windows version
    version = getversion(name, release, servicepack, architecture)

    ALERT("[E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin", ALERT.GOOD)
    ALERT("windows version identified as '%s'" % version, ALERT.GOOD)

    # spacer
    ALERT("")

    # vulns, the dictionary of the bulletins based off of the potential bulletins
    # also, a good opportunity to remove false-positives due to the
    # differences in the technet post and bulletin
    for row in potential:
        id = row[1]

        # start removing vulns because of false-positives
        # Manual override for MS11-011 to reduce false positives. The article was updated, but the bulletin database wasn't (https://technet.microsoft.com/en-us/library/security/ms11-011.aspx)
        # V1.2 (March 18, 2011): Added Windows 7 for 32-bit Systems Service Pack 1, Windows 7 for x64-based Systems Service Pack 1, Windows Server 2008 R2 for x64-based Systems Service Pack 1, and Windows Server 2008 R2 for Itanium-based Systems Service Pack 1 to Non-Affected Software. This is an informational change only. There were no changes to the security update files or detection logic.
        if id == 'MS11-011':
            ms11_011 = ['Windows 7 for 32-bit Systems Service Pack 1', 'Windows 7 for x64-based Systems Service Pack 1',
                        'Windows Server 2008 R2 for x64-based Systems Service Pack 1',
                        'Windows Server 2008 R2 for Itanium-based Systems Service Pack 1']
            for not_affected in ms11_011:
                compare_version = getversion(getname(not_affected), getrelease(not_affected),
                                             getservicepack(not_affected), getarchitecture(not_affected))
                if version == compare_version:
                    if ARGS.verbose: ALERT(
                        "Ignoring MS11-011 false positive due to it not affecting '%s'" % compare_version)
                    id = False

        for bulletinid in bulletinids:
            if bulletinid == id:
                title = row[5]
                kb = row[2]
                severity = row[3]
                if id not in ids:
                    vulns[id] = [title, kb, severity]
                    ids.add(id)

    # alerted, if a bulletin has been alerted to the user so that it doesn't appear twice
    #          this occurs when a bulletin has multiple parents
    # msids, the actual data for all of the relevant msids (the row from the CSV)
    alerted = set()
    msids = sorted(vulns, reverse=True)

    # loop through the bulletinids which is the set of the actual bulletins that are to
    # be alerted
    for msid in msids:

        ## don't alert twice, no matter the case
        if msid not in alerted:

            # get the msid, exploitability alert rating, and resources
            m, exploit, resources = getexploit(msid)

            # only display the message, if the exploit flag isn't used
            # or if it is used, and the alert level is MSF or EXP
            if ARGS.audit or (exploit == ALERT.MSF or exploit == ALERT.EXP):

                alert = ALERT.NORMAL
                if exploit: alert = exploit

                ALERT("%s: %s (%s) - %s" % (msid, vulns[msid][0], vulns[msid][1], vulns[msid][2]), alert)
                if resources and not ARGS.quiet:
                    for resource in resources:
                        ALERT("  %s" % resource)
                    ALERT("")

                alerted.add(msid)

                # only attempt to display linked/sub msids based on cli arguments
                if ARGS.sub:

                    # linked ms, the children of this msid
                    linked = set(get_linked_ms([msid], csv.reader(StringIO(database))))
                    linked = linked.intersection(msids)

                    # loop through the linked msids, and only display those that qualify and
                    # those that have not been alerted yet
                    for lmsid in sorted(linked, reverse=True):
                        if lmsid in msids and lmsid not in alerted:
                            lexploit = getexploit(lmsid)
                            lalert = ALERT.NORMAL
                            if ARGS.audit or (lexploit == ALERT.MSF or lexploit == ALERT.EXP):
                                if lexploit: lalert = lexploit
                                ALERT("|_%s: %s (%s) - %s" % (lmsid, vulns[lmsid][0], vulns[lmsid][1], vulns[lmsid][2]),
                                      lalert)

        # only allow duplicate events to be displayed when command-line args passed
        if not ARGS.duplicates: alerted.add('lmsid')

    # end run()


# attempt to detect character encoding of a file
# otherwise return None
# https://stackoverflow.com/questions/3323770/character-detection-in-a-text-file-in-python-using-the-universal-encoding-detect
def detect_encoding(filename):
    try:
        import chardet
        data = open(filename, "r").read()
        result = chardet.detect(data)
        encoding = result['encoding']
        return encoding
    except:
        return None


# the trace command is used to determine linked MS bulletins
# TODO much of this is duplicated from run(). should be merged
def trace(database):
    # convert to upper
    bulletinid = ARGS.trace.upper()
    ALERT("searching for bulletin id %s" % bulletinid)

    # get linked msids
    lmsids = get_linked_ms([bulletinid], csv.reader(StringIO(database)))

    msids = []

    if ARGS.ostext:
        ALERT("getting OS information from command line text")

        name = getname(ARGS.ostext)
        release = getrelease(ARGS.ostext)
        servicepack = getservicepack(ARGS.ostext)
        architecture = getarchitecture(ARGS.ostext)

        if ARGS.verbose:
            ALERT("name: %s" % name)
            ALERT("release: %s" % release)
            ALERT("service pack: %s" % servicepack)
            ALERT("architecture: %s" % architecture)

        # the os name at least has to be identified
        if not name:
            ALERT("unable to determine the windows version command line text from '%s'" % ARGS.ostext, ALERT.BAD)
            exit(1)

        # get linked msids, loop through the row
        for row in csv.reader(StringIO(database)):
            msid = row[1]
            affected = row[6]

            if msid in lmsids:
                # debug
                # print ("%s,%s,%s,%s,%s,%s" % (msid, name, release, servicepack, architecture, affected))

                if isaffected(name, release, servicepack, architecture, affected) and msid not in msids: msids.append(
                    msid)


    else:
        msids = lmsids

    ALERT("linked msids %s" % msids, ALERT.GOOD)


def patches(database):
    kbs = []

    # convert to upper
    bulletinid = ARGS.patches.upper()
    ALERT("searching all kb's for bulletin id %s" % bulletinid)

    # get linked msids, loop through the row
    for row in csv.reader(StringIO(database)):

        bulletinkb = row[2]
        componentkb = row[7]

        # if there's a match
        if bulletinid in row[1]:
            kbs.append(bulletinkb)
            kbs.append(componentkb)

    ALERT("relevant kbs %s" % (sorted(set(kbs), reverse=True)), ALERT.GOOD)


def getversion(name, release, servicepack, architecture):
    version = "Windows " + name

    # append release first
    if release: version += " R" + release

    # then service pack
    if servicepack: version += " SP" + servicepack

    # architecture
    if architecture == "Itanium":
        version += " Itanium-based"
    else:
        version += " %s-bit" % architecture

    return version


def getname(ostext):
    if ostext == False:
        return False

    osname = False

    osnamearray = [["xp", "XP"],
                   ["2000", "2000"],
                   ["2003", "2003"],
                   ["vista", "Vista"],
                   ["2008", "2008"],
                   [" 7", "7"],
                   [" 8", "8"],
                   ["2012", "2012"],
                   ["8.1", "8.1"],
                   [" 10", "10"]]

    for needle in osnamearray:
        ostext = ostext.lower()
        if "windows" + needle[0] in ostext or "windows " + needle[0] in ostext or "server" + needle[
            0] in ostext or "server " + needle[0] in ostext:
            osname = needle[1]

    # the first loop is a more restrictive detection of the OS name, but it does not detect the following
    # > Microsoft Windows\xFF7 Entreprise
    # so if there is no detection from the first attempt, then search on a more loosely based string of
    # needle and space
    if not osname:
        for needle in osnamearray:
            if needle[0] + " " in ostext.lower():
                osname = needle[1]

    return osname


def getrelease(ostext):
    if ostext == False:
        return False

    osrelease = False

    regex = "( r| rc|release|rel)[ ]*(\d)"
    m = re.search(regex, ostext.lower())

    if m and m.group(2):
        osrelease = m.group(2)

    return osrelease


def getservicepack(ostext):
    if ostext == False:
        return False

    servicepack = False

    regex = "(sp|pack|pack:)[ ]*(\d)"
    m = re.search(regex, ostext.lower())
    if m and m.group(2):
        servicepack = m.group(2)

    return servicepack


# architecture defaults to 32, but can be 64-bit
# or itanium based
def getarchitecture(ostext):
    # default to 32-bit
    architecture = "32"

    # haystack
    s = ostext.lower()

    # attempt to be as flexible as possible
    # matching '64-based', 'x64', ' 64', 'i64', '64bit', '64 bit', '64-bit'
    if ("64-based" in s) or ("x64" in s) or (" 64" in s) or ("i64" in s) or ("64bit" in s) or ("64 bit" in s) or (
            "64-bit" in s): architecture = "64"

    # target Itanium with a simple search for 'tani'
    if "tani" in s: architecture = "Itanium"

    if getname(ostext) == "2008" and getrelease(ostext) == "2" and architecture == "32":
        if ARGS.verbose:
            ALERT(
                "forcing unidentified architecture to 64-bit because OS identified as Windows 2008 R2 (although could be Itanium and wasn't detected?)")
        architecture = "64"

    # windows server 2012 is only 64-bit arch
    if getname(ostext) == "2012" and architecture == "32":
        if ARGS.verbose:
            ALERT(
                "forcing unidentified architecture to 64-bit because OS identified as Windows Server 2012 does not support 32-bit")
        architecture = "64"

    return architecture


# itanium build search string
def getitanium(ostext):
    if ostext == False:
        return False

    regex = "(tanium)"
    m = re.search(regex, ostext.lower())

    if m:
        return True

    return False


def getpatch(ostext):
    patch = False

    regex = "(\d){5,10}"
    m = re.search(regex, ostext.lower())
    if m and m.group():
        patch = m.group()

    return patch


# get the bulletin ids from the haystack
# these are typically in the form of: 
#   MS14-009[2898860]
#   MS13-052[2833940],MS14-009[2898856]
# will return a list if found, otherwise false
def get_bulletin_ids(haystack):
    regex = "MS[\d]{2,3}-[\d]{2,3}"
    m = re.findall(regex, haystack)
    if len(m) > 0:
        return m
    return False


def isaffected(name, release, servicepack, architecture, haystack):
    if name == getname(haystack):

        # ensure None are set to False
        # example, if getservicepack() does not get called in the systeminfo parsing
        # then servicepack will be None. this will then fail when comparing to False.
        if release == None:
            release = False
        if servicepack == None:
            servicepack = False
        if architecture == None:
            architecture = False

        n = (name == getname(haystack))
        r = (release == getrelease(haystack))
        s = (servicepack == getservicepack(haystack))
        a = (architecture == getarchitecture(haystack))

        # we ignore the architecture for 2012 servers, as there is only 64-bit
        if name == "2012":
            return r and s

        return a and r and s


# search entire database for linked msids
# this will also search the superseded column (11)
def get_linked_ms(ms_ids, database):
    ms_id_list = []

    # go through each row in the database
    for row in database:

        # base MS-XX
        rowid = row[1]

        # superseded MS-XX

        # @TODO check if it can be removed or simplified.
        # first try row 12, and then row 11 for the supercedes column due to
        # differences in csv and xlrd parsing. this was a bug that might be
        # fixed now
        bulletin_ids = get_bulletin_ids(row[12])
        if not bulletin_ids:
            bulletin_ids = get_bulletin_ids(row[11])

        bulletin_ids = merge_list(bulletin_ids)

        # loop through each msid for each row
        for ms_id in ms_ids:
            # if the ms_id matches the row, get the supercedes column (which is a list)
            if ms_id == rowid or rowid in ms_id_list:
                ms_id_list.append(ms_id)
                ms_id_list = ms_id_list + bulletin_ids

    return sorted(set(ms_id_list), reverse=True)


# determines whether or not an msid is in a list of exploits. if msid = 0
# then it will just return the count
def getexploit(msid=0):
    # bulletin, type, details
    exploits = [

        ['MS16-135', ALERT.EXP, [  # CVE-2016-7255
            "https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)",
            "https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)",
            "https://github.com/tinysec/public/tree/master/CVE-2016-7255"]],

        ['MS16-129', ALERT.EXP, [  # CVE 2016-7200, CVE-2016-7201
            "https://www.exploit-db.com/exploits/40990/ -- Microsoft Edge (Windows 10) - 'chakra.dll' Info Leak / Type Confusion Remote Code Execution",
            "https://github.com/theori-io/chakra-2016-11"]],

        ['MS16-098', ALERT.EXP, [
            "https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)"]],

        ['MS16-075', ALERT.MSF, [
            "https://github.com/foxglovesec/RottenPotato",
            "https://github.com/Kevin-Robertson/Tater",
            "https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege",
            "https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation"]],

        ['MS16-074', ALERT.EXP, [  # CVE 2016-3216
            "https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC",
            "https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC"]],
        # CVE 2016-3220

        ['MS16-063', ALERT.EXP, [  # CVE 2016-0199
            "https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC"]],

        ['MS16-042', ALERT.EXP, [  # CVE 2016-0122
            "https://www.exploit-db.com/exploits/39694/ -- Microsoft Office Excel Out-of-Bounds Read Remote Code Execution (MS16-042), PoC"]],

        ['MS16-059', ALERT.EXP, [  # CVE 2016-0185
            "https://www.exploit-db.com/exploits/39805/ -- Microsoft Windows Media Center - .MCL File Processing Remote Code Execution (MS16-059), PoC"]],

        ['MS16-056', ALERT.EXP, [  # CVE-2015-1730
            "https://www.exploit-db.com/exploits/40881/ -- Microsoft Internet Explorer - jscript9 JavaScriptStackWalker Memory Corruption (MS15-056)",
            "http://blog.skylined.nl/20161206001.html -- MSIE jscript9 JavaScriptStackWalker memory corruption"]],

        ['MS16-032', ALERT.EXP, [  # CVE 2016-0099
            "https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF",
            "https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC",
            "https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC",
            "https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)"]],

        ['MS16-016', ALERT.MSF, [  # CVE 2016-0051
            "https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF",
            "https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC",
            "https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC"]],

        ['MS16-014', ALERT.EXP, [  # CVE 2016-0400
            "Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC"]],

        ['MS16-007', ALERT.EXP, [  # CVE 2016-0015, CVE 2016-0016
            "https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC",
            "https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC"]],

        ['MS15-134', ALERT.EXP, [  # CVE 2015-6131
            "https://www.exploit-db.com/exploits/38911/ -- Microsoft Windows Media Center Library Parsing RCE Vulnerability aka self-executing' MCL File, PoC",
            "https://www.exploit-db.com/exploits/38912/ -- Microsoft Windows Media Center Link File Incorrectly Resolved Reference, PoC",
            "https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object - 'els.dll' DLL Planting (MS15-134)",
            "https://code.google.com/p/google-security-research/issues/detail?id=514 -- Microsoft Office / COM Object DLL Planting with els.dll"]],

        ['MS15-132', ALERT.EXP, [  # CVE 2015-6132, CVE 2015-6128
            "https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC",
            "https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC"]],

        ['MS15-112', ALERT.EXP, [  # CVE 2015-6086
            "https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)"]],

        ['MS15-111', ALERT.EXP, [  # CVE 2015-2553
            "https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC"]],

        ['MS15-102', ALERT.EXP, [  # CVE 2015-2524, CVE 2015-2525, CVE 2015-2528
            "https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC",
            "https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC",
            "https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC"]],

        ['MS15-100', ALERT.MSF, [  # CVE 2015-2509
            "https://www.exploit-db.com/exploits/38195/ -- MS15-100 Microsoft Windows Media Center MCL Vulnerability, MSF",
            "https://www.exploit-db.com/exploits/38151/ -- Windows Media Center - Command Execution (MS15-100), PoC"]],

        ['MS15-097', ALERT.EXP, [  # CVE 2015-2508, CVE 2015-2527
            "https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC",
            "https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC"]],

        ['MS15-078', ALERT.MSF, [  # CVE 2015-2426, CVE 2015-2433
            "https://www.exploit-db.com/exploits/38222/ -- MS15-078 Microsoft Windows Font Driver Buffer Overflow"]],

        ['MS15-052', ALERT.EXP, [  # CVE 2015-1674
            "https://www.exploit-db.com/exploits/37052/ -- Windows - CNG.SYS Kernel Security Feature Bypass PoC (MS15-052), PoC"]],

        ['MS15-051', ALERT.MSF, [  # CVE 2015-1701
            "https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC",
            "https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF"]],

        ['MS15-022', ALERT.EXP, [  # CVE 2015-0097
            "https://www.exploit-db.com/exploits/37657/ -- Microsoft Word Local Machine Zone Remote Code Execution Vulnerability, PoC",
            "https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/sploits/37657.zip"]],

        ['MS15-010', ALERT.EXP, [  # CVE 2015-0057
            "https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC",
            "https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC",
            "https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC"]],

        ['MS15-001', ALERT.EXP, [  # CVE 2015-0002
            "http://www.exploit-db.com/exploits/35661/ -- Windows 8.1 (32/64 bit) - Privilege Escalation (ahcache.sys/NtApphelpCacheControl), PoC"]],

        ['MS14-070', ALERT.EXP, [  # CVE 2014 4076
            "http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC"]],

        ['MS14-068', ALERT.EXP, [  # CVE 2014-6324
            "http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC"]],

        ['MS14-064', ALERT.MSF, [  # CVE 2014-6332
            "https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC",
            "http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC",
            "http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC",
            "http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF",
            "http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF",
            "http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF"]],

        ['MS14-062', ALERT.MSF, [  # CVE 2014-4971
            "http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC",
            "http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation"]],

        ['MS14-060', ALERT.MSF, [  # CVE 2014-4114
            "http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC",
            "http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF"]],

        ['MS14-058', ALERT.MSF, [  # CVE 2014-4113
            "http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF"]],

        ['MS14-040', ALERT.EXP, [  # CVE 2014-1767
            "https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC",
            "https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC"]],

        ['MS14-035', ALERT.EXP],
        ['MS14-029', ALERT.EXP, [
            "http://www.exploit-db.com/exploits/34458/"]],

        ['MS14-026', ALERT.EXP, [  # CVE 2014-1806
            "http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC"]],

        ['MS14-017', ALERT.MSF],
        ['MS14-012', ALERT.MSF],
        ['MS14-009', ALERT.MSF],
        ['MS14-002', ALERT.EXP],
        ['MS13-101', ALERT.EXP],
        ['MS13-097', ALERT.MSF],
        ['MS13-096', ALERT.MSF],
        ['MS13-090', ALERT.MSF],
        ['MS13-080', ALERT.MSF],
        ['MS13-071', ALERT.MSF],
        ['MS13-069', ALERT.MSF],
        ['MS13-067', ALERT.EXP],
        ['MS13-059', ALERT.MSF],
        ['MS13-055', ALERT.MSF],
        ['MS13-053', ALERT.MSF],
        ['MS13-009', ALERT.MSF],
        ['MS13-005', ALERT.MSF],
        ['MS12-037', ALERT.EXP, [  # CVE 2012-1876
            "http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC",
            "http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC"]],

        ['MS12-022', ALERT.MSF],
        ['MS11-080', ALERT.MSF],
        ['MS11-011', ALERT.EXP],
        ['MS10-073', ALERT.MSF],
        ['MS10-061', ALERT.MSF],
        ['MS10-059', ALERT.EXP],
        ['MS10-047', ALERT.EXP],
        ['MS10-015', ALERT.MSF],
        ['MS10-002', ALERT.MSF],
        ['MS09-072', ALERT.MSF],
        ['MS09-067', ALERT.MSF],
        ['MS09-065', ALERT.MSF],
        ['MS09-053', ALERT.MSF],
        ['MS09-050', ALERT.MSF, [
            "https://www.rapid7.com/db/modules/exploit/windows/smb/ms09_050_smb2_negotiate_func_index -- MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference"]],

        ['MS09-050', ALERT.MSF],
        ['MS09-043', ALERT.MSF],
        ['MS09-020', ALERT.MSF],
        ['MS09-004', ALERT.MSF],
        ['MS09-002', ALERT.MSF],
        ['MS09-001', ALERT.MSF],
        ['MS08-078', ALERT.MSF],
        ['MS08-070', ALERT.MSF],
        ['MS08-067', ALERT.MSF],
        ['MS08-067', ALERT.MSF],
        ['MS08-053', ALERT.MSF],
        ['MS08-041', ALERT.MSF],
        ['MS08-025', ALERT.EXP],
        ['MS07-065', ALERT.MSF],
        ['MS07-065', ALERT.MSF],
        ['MS07-064', ALERT.MSF],
        ['MS07-029', ALERT.MSF],
        ['MS07-029', ALERT.MSF],
        ['MS07-017', ALERT.MSF],
        ['MS06-071', ALERT.MSF],
        ['MS06-070', ALERT.MSF],
        ['MS06-070', ALERT.MSF],
        ['MS06-067', ALERT.MSF],
        ['MS06-066', ALERT.MSF],
        ['MS06-066', ALERT.MSF],
        ['MS06-063', ALERT.MSF],
        ['MS06-057', ALERT.MSF],
        ['MS06-055', ALERT.MSF],
        ['MS06-049', ALERT.EXP],
        ['MS06-040', ALERT.MSF],
        ['MS06-040', ALERT.MSF],
        ['MS06-035', ALERT.MSF],
        ['MS06-025', ALERT.MSF],
        ['MS06-025', ALERT.MSF],
        ['MS06-019', ALERT.MSF],
        ['MS06-013', ALERT.MSF],
        ['MS06-001', ALERT.MSF],
        ['MS05-054', ALERT.MSF],
        ['MS05-047', ALERT.MSF],
        ['MS05-039', ALERT.MSF],
        ['MS05-039', ALERT.MSF],
        ['MS05-030', ALERT.MSF],
        ['MS05-017', ALERT.MSF],
        ['MS05-017', ALERT.MSF],
        ['MS04-045', ALERT.MSF],
        ['MS04-031', ALERT.MSF],
        ['MS04-031', ALERT.MSF],
        ['MS04-011', ALERT.MSF],
        ['MS04-011', ALERT.MSF],
        ['MS04-007', ALERT.MSF],
        ['MS04-007', ALERT.MSF],
        ['MS03-051', ALERT.MSF],
        ['MS03-049', ALERT.MSF],
        ['MS03-049', ALERT.MSF],
        ['MS03-046', ALERT.MSF],
        ['MS03-026', ALERT.MSF],
        ['MS03-026', ALERT.MSF],
        ['MS03-022', ALERT.MSF],
        ['MS03-020', ALERT.MSF],
        ['MS03-007', ALERT.MSF],
        ['MS02-065', ALERT.MSF],
        ['MS02-063', ALERT.MSF],
        ['MS02-056', ALERT.MSF],
        ['MS02-039', ALERT.MSF],
        ['MS02-018', ALERT.MSF],
        ['MS01-033', ALERT.MSF],
        ['MS01-026', ALERT.MSF],
        ['MS01-023', ALERT.MSF],
        ['MS00-094', ALERT.MSF]
    ]

    # return the count of exploits
    if msid == 0:
        return len(exploits)

    for exploit in exploits:
        if msid == exploit[0]:
            # need 3 values to unpack, in case there are resources
            if len(exploit) == 2:
                exploit.append(None)
                return exploit

            # otherwise there are 3 values
            return exploit

    return [False, False, False]


# the update function
def update():
    # compute the filenames to be used
    filenames = '%s-mssb' % datetime.datetime.now().strftime('%Y-%m-%d')
    xls_file = '%s.%s' % (filenames, 'xlsx')

    # url request opener with user-agent
    opener = urllib.request.build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36')]

    # grab the new data from ms and scrape the site
    # try:
    #  response = opener.open(MSSB_URL)
    # except urllib2.URLError, e:
    #  ALERT("error getting url %s" % MSSB_URL, ALERT.BAD)
    #  exit(1)
    #
    # ALERT("successfully requested base url")

    # 2016-02-10, ms changed link to http://download.microsoft.com/download/6/7/3/673E4349-1CA5-40B9-8879-095C72D5B49D/BulletinSearch.xlsx
    #
    # now parse the data, ensure we have an mssb link
    # <td>BulletinSearch_20131111_151603.xlsx <span class="green-sniff-recommend">(recommended)</span></td>
    # html = response.read()
    # m = re.findall('url=(.*BulletinSearch.*.xls[x]*)', html)
    # m = re.findall('href="(.*BulletinSearch.*.xlsx)"', html) # old bulletin request url, 20140502

    # ensure we get the bulletin search
    # if m and m[0]:
    bulletinUrl = BULLETIN_URL
    #  ALERT("scraped ms download url")
    # if the file was xlsx, add an x to the extension
    #  if "xlsx" in bulletinUrl: xlsFile += "x"
    # else:
    #  ALERT("error finding the ms download url from previous response", ALERT.BAD)
    #  exit(1)

    # now download the mssb file, with a random sleep
    response = None
    try:
        # sleep(randint(1,3))
        response = opener.open(bulletinUrl)
    except urllib.error.URLError:
        ALERT("error getting ms sb url %s" % bulletinUrl, ALERT.BAD)
        exit(1)

    bulletin_data = response.read()

    ALERT("writing to file %s" % xls_file, ALERT.GOOD)
    f = open(xls_file, 'wb')
    f.write(bulletin_data)
    f.close


# modified ALERT class for exploit and metasploit level logging
class ALERT(object):

    def __init__(self, message, level=0, ansi=True):

        # default to ansi alerting, if it's detected as windows platform then disable
        if platform.system() == "Windows":
            ansi = False

        good = '[+]'
        bad = '[-]'
        normal = '[*]'

        msf = '[M]'
        exploit = '[E]'

        if ansi:
            if level == ALERT.GOOD:
                print("%s%s%s" % ('\033[1;32m', good, "\033[0;0m"), end=''),
            elif level == ALERT.BAD:
                print("%s%s%s" % ('\033[1;31m', bad, "\033[0;0m"), end=''),
            elif level == ALERT.MSF:
                print("%s%s%s" % ('\033[1;32m', msf, "\033[0;0m"), end=''),
            elif level == ALERT.EXP:
                print("%s%s%s" % ('\033[1;32m', exploit, "\033[0;0m"), end=''),
            else:
                print("%s%s%s" % ('\033[1;34m', normal, "\033[0;0m"), end=''),

        else:
            if level == ALERT.GOOD:
                print('%s' % good, end=''),
            elif level == ALERT.BAD:
                print('%s' % bad, end=''),
            elif level == ALERT.MSF:
                print('%s' % msf, end=''),
            elif level == ALERT.EXP:
                print('%s' % exploit, end=''),
            else:
                print('%s' % normal, end=''),

        print(message)

    @staticmethod
    @property
    def BAD(self):
        return -1

    @staticmethod
    @property
    def NORMAL(self):
        return 0

    @staticmethod
    @property
    def GOOD(self):
        return 1

    @staticmethod
    @property
    def MSF(self):
        return 2

    @staticmethod
    @property
    def EXP(self):
        return 3


# this helper function will merge a list of lists into one sorted set
def merge_list(items):
    s = []
    if items:
        for item in items:
            if isinstance(item, list):
                s = s + item
            else:
                s.append(item)
    return s


if __name__ == '__main__':
    main()
