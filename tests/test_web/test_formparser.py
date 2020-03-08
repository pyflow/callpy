
from callflow.web.formparsers import QueryStringParser, MultiPartParser
import pytest

def test_query_strint_parser():
    p = QueryStringParser()
    p.feed(b'a=b&b=c')
    p.feed(b'')
    msgs = p.gets()
    assert len(msgs) == 2
    assert msgs[0] == ('a', 'b')
    assert msgs[1] == ('b', 'c')

simple_field_form = b'''------WebKitFormBoundaryTkr3kCBQlBe1nrhc\r
Content-Disposition: form-data; name="field"\r
\r
This is a test.\r
------WebKitFormBoundaryTkr3kCBQlBe1nrhc--'''

@pytest.mark.asyncio
async def test_form_data_parser():
    p = MultiPartParser(None, None)
    boundary = b'----WebKitFormBoundaryTkr3kCBQlBe1nrhc'
    p.boundary = boundary
    await p.feed(simple_field_form)
    await p.feed('')
    assert len(p.parts) == 1
    part = p.parts[0]
    assert part.get() == ('field', "This is a test.")