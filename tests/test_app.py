# -*- coding: utf-8 -*-
import pytest

from callflow.app import CallFlow
from callflow.web.request import RequestContextGlobals
import copy
import traceback


def test_basic_app():
    app = CallFlow(__name__)
    app.add_url_rule('/hello', 'hello', lambda x: 'ok')

    with pytest.raises(AssertionError):
        app.add_url_rule('/hello', 'hello', lambda x: 'ok')

    @app.endpoint('foo')
    def foo():
        return 'foo'
    app.add_url_rule('/foo', 'foo')

    def error_handler(exception):
        return '500'

    app.register_error_handler(Exception, error_handler)

