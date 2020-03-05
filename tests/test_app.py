# -*- coding: utf-8 -*-
import pytest

from callflow.app import CallFlow
import copy
import traceback


def test_basic_app():
    app = CallFlow(__name__)
    async def hello(req):
        return 'ok'

    app.add_url_rule('/hello', 'hello', hello)

    async def hello2(req):
        return 'ok'

    with pytest.raises(AssertionError):
        app.add_url_rule('/hello', 'hello', hello2)

    @app.endpoint('foo')
    async def foo(req):
        return 'foo'
    app.add_url_rule('/foo', 'foo')

    async def error_handler(error):
        return '500'

    app.register_error_handler(500, error_handler)

