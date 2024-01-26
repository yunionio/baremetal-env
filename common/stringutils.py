# encoding: utf-8
from __future__ import unicode_literals


def ensure_ascii(s):
    if s is None:
        return s
    if isinstance(s, str):
        return s
    else:
        return s.encode('utf-8')


def ensure_length(s, maxlen):
    assert(maxlen > 3)
    if len(s) <= maxlen:
        return s
    else:
        return s[:(maxlen-3)] + '...'


def compare_str(str1, str2):
    if str1 > str2:
        return 1
    elif str1 < str2:
        return -1
    else:
        return 0
