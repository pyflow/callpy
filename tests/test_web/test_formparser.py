
from callflow.web.formparsers import QuerystringParser

def test_query_strint_parser():
    p = QuerystringParser()
    p.feed(b'a=b&b=c')
    p.feed(b'')
    msgs = p.gets()
    assert len(msgs) == 2
    assert msgs[0] == ('a', 'b')
    assert msgs[1] == ('b', 'c')