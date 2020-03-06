import pytest

from callflow.web.datastructures import MultiDict, FormsDict
import base64
from callflow.web.utils import to_unicode, to_bytes
from io import BytesIO
import tempfile
import os

def test_basic_multidict():
    d = MultiDict([('a', 'b'), ('a', 'c')])
    assert d['a'] == 'b'
    assert d.getlist('a') == ['b', 'c']
    assert ('a' in d) == True

    d = MultiDict([('a', 'b'), ('a', 'c')], a='dddd')
    assert d['a'] == 'b'
    assert d.getlist('a') == ['b', 'c', 'dddd']
    assert len(d) == 1
    assert list(d.keys()) == ['a']
    assert list(d.values()) == ['b']
    d.replace('a', 'ee')
    assert d['a'] == 'ee'
    assert d.getlist('a') == ['ee']
    assert d.get('foo') == None

    del d['a']
    assert len(d) == 0


def test_formsdict():
    form = FormsDict({'a': '111', 'b':123, 'c':b'xxx'}.items())
    assert form.a == '111'
    assert form.b == 123
    assert form.c == 'xxx'
    assert form.d == ''

