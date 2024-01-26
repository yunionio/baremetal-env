# regular express utility functions
import unittest
import re

UUID_REG = re.compile(r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}')
def match_uuid(string):
    global UUID_REG
    return UUID_REG.match(string) is not None

UUID_EXACT_REG = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')
def match_uuid_exact(string):
    global UUID_EXACT_REG
    return UUID_EXACT_REG.match(string) is not None

INTEGER_REG = re.compile(r'^[0-9]+$')
def match_integer(string):
    global INTEGER_REG
    return INTEGER_REG.match(string) is not None

FLOAT_REG = re.compile(r'^\d+(\.\d*)?$')
def match_float(string):
    global FLOAT_REG
    return FLOAT_REG.match(string) is not None


MACADDR_REG = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
def match_macaddr(string):
    global MACADDR_REG
    return MACADDR_REG.match(string) is not None

MACADDR_FUZZY_REG = re.compile(r'^(?=[0-9a-zA-Z:]+$)[0-9a-zA-Z:]{1,17}')
def fuzzy_match_macaddr(string):
    global MACADDR_FUZZY_REG
    return MACADDR_FUZZY_REG.match(string) is not None

IPADDR_FUZZY_REG = re.compile(r'^(?=[0-9\.]+$)[0-9\.]{1,39}')
def fuzzy_match_ipaddr(string):
    global IPADDR_FUZZY_REG
    return IPADDR_FUZZY_REG.match(string) is not None

COMPACT_MACADDR_REG = re.compile(r'^[0-9a-fA-F]{12}$')
def match_compact_macaddr(string):
    global COMPACT_MACADDR_REG
    return COMPACT_MACADDR_REG.match(string) is not None


IPADDR_REG_PATTERN = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
IPADDR_REG = re.compile(IPADDR_REG_PATTERN)
def match_ip4addr(string):
    global IPADDR_REG
    return IPADDR_REG.match(string) is not None


IP6ADDR_REG = re.compile(r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(%.+)?\s*$")
def match_ip6addr(string):
    global IP6ADDR_REG
    return IP6ADDR_REG.match(string) is not None


def match_ipaddr(string):
    return match_ip4addr(string) or match_ip6addr(string)


NSPTR_REG = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.in-addr\.arpa$')
def match_ptr(string):
    global NSPTR_REG
    return NSPTR_REG.match(string) is not None


NAME_REG = re.compile(r'^[a-zA-Z][a-zA-Z0-9._@-]*$')
def match_name(string):
    global NAME_REG
    return NAME_REG.match(string) is not None

DOMAINNAME_REG = re.compile(r'^[a-zA-Z0-9-.]+$')
def match_domainname(string):
    global DOMAINNAME_REG
    return DOMAINNAME_REG.match(string) is not None

DOMAINSRV_REG = re.compile(r'^[a-zA-Z0-9-._]+$')
def match_domainsrv(string):
    global DOMAINSRV_REG
    return DOMAINSRV_REG.match(string) is not None

SIZE_REG = re.compile(r'^\d+[bBkKmMgG]?$')
def match_size(string):
    if isinstance(string, int):
        return True
    if isinstance(string, float):
        return True
    global SIZE_REG
    return SIZE_REG.match(string) is not None

MONTH_REG = re.compile(r'^\d{4}-\d{2}$')
def match_month(string):
    global MONTH_REG
    return MONTH_REG.match(string) is not None

DATE_REG = re.compile(r'^\d{4}-\d{2}-\d{2}$')
def match_date(string):
    global DATE_REG
    return DATE_REG.match(string) is not None

DATE_COMPACT_REG = re.compile(r'^\d{8}$')
def match_date_compact(string):
    global DATE_COMPACT_REG
    return DATE_COMPACT_REG.match(string) is not None

ISO_TIME_REG = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
def match_isotime(string):
    global ISO_TIME_REG
    return ISO_TIME_REG.match(string) is not None

FULLISO_TIME_REG = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$')
def match_fullisotime(string):
    global FULLISO_TIME_REG
    return FULLISO_TIME_REG.match(string) is not None


COMPACT_TIME_REG = re.compile(r'^\d{14}$')
def match_compact_time(string):
    global COMPACT_TIME_REG
    return COMPACT_TIME_REG.match(string) is not None

MYSQL_TIME_REG = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$')
def match_mysql_time(string):
    global MYSQL_TIME_REG
    return MYSQL_TIME_REG.match(string) is not None

RFC2882_TIME_REG = re.compile(r'[A-Z][a-z]{2}, [0-9]{1,2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [A-Z]{3}')
def match_rfc2882_time(string):
    global RFC2882_TIME_REG
    return RFC2882_TIME_REG.match(string) is not None

EMAIL_REG = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4}$')
def match_email(string):
    global EMAIL_REG
    return EMAIL_REG.match(string) is not None

CHINA_MOBILE_REG = re.compile(r'^1[0-9-]{10}$')
def match_mobile(string):
    global CHINA_MOBILE_REG
    return CHINA_MOBILE_REG.match(string) is not None

FS_FORMAT_REG = re.compile(r'^(ext|fat|hfs|xfs|swap|ntfs|reiserfs|ufs|btrfs)')
def match_fs_format(string):
    global FS_FORMAT_REG
    return FS_FORMAT_REG.match(string) is not None


class RegTest(unittest.TestCase):

    def test_fuzzy_mac(self):
        self.assertEquals(fuzzy_match_macaddr("hello"), True)
        self.assertEquals(fuzzy_match_macaddr("2,12"), False)
        self.assertEquals(fuzzy_match_macaddr("123-jlas"), False)
        self.assertEquals(fuzzy_match_macaddr("123:jlas"), True)

    def test_fuzzy_ip(self):
        self.assertEquals(fuzzy_match_ipaddr("hello"), False)
        self.assertEquals(fuzzy_match_ipaddr("2,12"), False)
        self.assertEquals(fuzzy_match_ipaddr("123-jlas"), False)
        self.assertEquals(fuzzy_match_ipaddr("123:jlas"), False)
        self.assertEquals(fuzzy_match_ipaddr("123."), True)

if __name__ == '__main__':
    unittest.main()
    # import sys
    # if len(sys.argv) > 1:
    #     main_model = sys.modules['__main__']
    #     for matcher in (a for a in dir(main_model) if a.startswith('match_')):
    #         func = getattr(main_model, matcher)
    #         print matcher, func(sys.argv[1])
    # else:
    #     print "Usage: regutils <string>"
