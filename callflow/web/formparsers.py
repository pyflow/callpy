import os
import re
import sys
from io import BytesIO
from numbers import Number
import typing
from enum import Enum
from urllib.parse import unquote_plus

from .datastructures import FormData, Headers, UploadFile
from basepy.asynclog import logger


# Flags for the multipart parser.
FLAG_PART_BOUNDARY              = 1
FLAG_LAST_BOUNDARY              = 2

# Get constants.  Since iterating over a str on Python 2 gives you a 1-length
# string, but iterating over a bytes object on Python 3 gives you an integer,
# we need to save these constants.
CR = b'\r'[0]
LF = b'\n'[0]
COLON = b':'[0]
SPACE = b' '[0]
HYPHEN = b'-'[0]
AMPERSAND = b'&'[0]
SEMICOLON = b';'[0]
LOWER_A = b'a'[0]
LOWER_Z = b'z'[0]
NULL = b'\x00'[0]


lower_char = lambda c: c | 0x20
ord_char = lambda c: c
join_bytes = lambda b: bytes(list(b))

# These are regexes for parsing header values.
SPECIAL_CHARS = re.escape(b'()<>@,;:\\"/[]?={} \t')
QUOTED_STR = br'"(?:\\.|[^"])*"'
VALUE_STR = br'(?:[^' + SPECIAL_CHARS + br']+|' + QUOTED_STR + br')'
OPTION_RE_STR = (
    br'(?:;|^)\s*([^' + SPECIAL_CHARS + br']+)\s*=\s*(' + VALUE_STR + br')'
)
OPTION_RE = re.compile(OPTION_RE_STR)
QUOTE = b'"'[0]


def parse_options_header(value):
    """
    Parses a Content-Type header into a value in the following format:
        (content_type, {parameters})
    """
    if not value:
        return (b'', {})

    # If we are passed a string, we assume that it conforms to WSGI and does
    # not contain any code point that's not in latin-1.
    if isinstance(value, str):            # pragma: no cover
        value = value.encode('latin-1')

    # If we have no options, return the string as-is.
    if b';' not in value:
        return (value.lower().strip(), {})

    # Split at the first semicolon, to get our value and then options.
    ctype, rest = value.split(b';', 1)
    options = {}

    # Parse the options.
    for match in OPTION_RE.finditer(rest):
        key = match.group(1).lower()
        value = match.group(2)
        if value[0] == QUOTE and value[-1] == QUOTE:
            # Unquote the value.
            value = value[1:-1]
            value = value.replace(b'\\\\', b'\\').replace(b'\\"', b'"')

        # If the value is a filename, we need to fix a bug on IE6 that sends
        # the full file path instead of the filename.
        if key == b'filename':
            if value[1:3] == b':\\' or value[:2] == b'\\\\':
                value = value.split(b'\\')[-1]

        options[key] = value

    return ctype, options

class ParseError(ValueError):
    offset = -1


class MultipartParseError(ParseError):
    pass


class QuerystringParseError(ParseError):
    pass


class QuerystringParser():
    def __init__(self, strict_parsing=False,
                 max_size=float('inf')):
        self.buffer = bytes()
        self.messages = []
        self.logger = logger.sync()

        # Max-size stuff
        if not isinstance(max_size, Number) or max_size < 1:
            raise ValueError("max_size must be a positive number, not %r" %
                             max_size)
        self.max_size = max_size
        self._current_size = 0

        # Should parsing be strict?
        self.strict_parsing = strict_parsing

    def feed(self, data):
        data_len = len(data)
        if (self._current_size + data_len) > self.max_size:
            # We truncate the length of data that we are to process.
            new_size = int(self.max_size - self._current_size)
            self.logger.warning("Current size is %d (max %d), so truncating "
                                "data length from %d to %d",
                                self._current_size, self.max_size, data_len,
                                new_size)
            data_len = new_size

        try:
            self._internal_feed(data, data_len)
        finally:
            self._current_size += data_len

    def _internal_feed(self, data, length):
        strict_parsing = self.strict_parsing

        if data:
            self.buffer += data
            no_more_data = False
        else:
            no_more_data = True

        i = 0
        data_len = len(self.buffer)

        buffer = self.buffer
        while i < data_len:
            sep_pos = buffer.find(b'&', i)
            if sep_pos == -1:
                sep_pos = buffer.find(b';', i)
                if sep_pos == -1 and no_more_data:
                    sep_pos = data_len+1

            if sep_pos == -1:
                break

            equal_pos = buffer.find(b'=', i, sep_pos)
            if equal_pos == -1:
                if strict_parsing:
                    raise QuerystringParseError('not found = in pair, got {}'.format(buffer[:sep_pos]))
                pair = (unquote_plus(buffer[i:sep_pos].decode('latin-1')), None)
            else:
                pair = (unquote_plus(buffer[i:equal_pos].decode('latin-1')),
                    unquote_plus(buffer[equal_pos+1:sep_pos].decode('latin-1')))

            self.messages.append(pair)
            i += (sep_pos + 1)

        if i > 0:
            self.buffer = self.buffer[i:]


    def gets(self):
        messages = self.messages
        self.messages = []
        return messages

    def __repr__(self):
        return "%s(strict_parsing=%r, max_size=%r)" % (
            self.__class__.__name__, self.strict_parsing, self.max_size
        )


class MultiPartMessage(Enum):
    PART_BEGIN = 1
    PART_DATA = 2
    PART_END = 3
    HEADER_FIELD = 4
    HEADER_VALUE = 5
    HEADER_END = 6
    HEADERS_FINISHED = 7
    END = 8


def _user_safe_decode(src: bytes, codec: str) -> str:
    try:
        return src.decode(codec)
    except (UnicodeDecodeError, LookupError):
        return src.decode("latin-1")


class FormParser:
    def __init__(
        self, headers: Headers, stream: typing.AsyncGenerator[bytes, None]
    ) -> None:
        self.headers = headers
        self.stream = stream

    async def parse(self) -> FormData:
        # Create the parser.
        parser = QuerystringParser()
        # Feed the parser with data from the request.
        async for chunk in self.stream:
            if chunk:
                parser.feed(chunk)
            else:
                parser.feed(b"")
            messages = parser.gets()

        return FormData(messages)


class MultiPartParser:
    def __init__(
        self, headers: Headers, stream: typing.AsyncGenerator[bytes, None]
    ) -> None:
        self.headers = headers
        self.stream = stream
        self.messages = []  # type: typing.List[typing.Tuple[MultiPartMessage, bytes]]

    def on_part_begin(self) -> None:
        message = (MultiPartMessage.PART_BEGIN, b"")
        self.messages.append(message)

    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        message = (MultiPartMessage.PART_DATA, data[start:end])
        self.messages.append(message)

    def on_part_end(self) -> None:
        message = (MultiPartMessage.PART_END, b"")
        self.messages.append(message)

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        message = (MultiPartMessage.HEADER_FIELD, data[start:end])
        self.messages.append(message)

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        message = (MultiPartMessage.HEADER_VALUE, data[start:end])
        self.messages.append(message)

    def on_header_end(self) -> None:
        message = (MultiPartMessage.HEADER_END, b"")
        self.messages.append(message)

    def on_headers_finished(self) -> None:
        message = (MultiPartMessage.HEADERS_FINISHED, b"")
        self.messages.append(message)

    def on_end(self) -> None:
        message = (MultiPartMessage.END, b"")
        self.messages.append(message)

    async def parse(self) -> FormData:
        # Parse the Content-Type header to get the multipart boundary.
        content_type, params = parse_options_header(self.headers["Content-Type"])
        charset = params.get(b"charset", "utf-8")
        if type(charset) == bytes:
            charset = charset.decode("latin-1")
        boundary = params.get(b"boundary")

        # Callbacks dictionary.
        callbacks = {
            "on_part_begin": self.on_part_begin,
            "on_part_data": self.on_part_data,
            "on_part_end": self.on_part_end,
            "on_header_field": self.on_header_field,
            "on_header_value": self.on_header_value,
            "on_header_end": self.on_header_end,
            "on_headers_finished": self.on_headers_finished,
            "on_end": self.on_end,
        }

        # Create the parser.
        parser = multipart.MultipartParser(boundary, callbacks)
        header_field = b""
        header_value = b""
        content_disposition = None
        content_type = b""
        field_name = ""
        data = b""
        file = None  # type: typing.Optional[UploadFile]

        items = (
            []
        )  # type: typing.List[typing.Tuple[str, typing.Union[str, UploadFile]]]

        # Feed the parser with data from the request.
        async for chunk in self.stream:
            parser.write(chunk)
            messages = list(self.messages)
            self.messages.clear()
            for message_type, message_bytes in messages:
                if message_type == MultiPartMessage.PART_BEGIN:
                    content_disposition = None
                    content_type = b""
                    data = b""
                elif message_type == MultiPartMessage.HEADER_FIELD:
                    header_field += message_bytes
                elif message_type == MultiPartMessage.HEADER_VALUE:
                    header_value += message_bytes
                elif message_type == MultiPartMessage.HEADER_END:
                    field = header_field.lower()
                    if field == b"content-disposition":
                        content_disposition = header_value
                    elif field == b"content-type":
                        content_type = header_value
                    header_field = b""
                    header_value = b""
                elif message_type == MultiPartMessage.HEADERS_FINISHED:
                    disposition, options = parse_options_header(content_disposition)
                    field_name = _user_safe_decode(options[b"name"], charset)
                    if b"filename" in options:
                        filename = _user_safe_decode(options[b"filename"], charset)
                        file = UploadFile(
                            filename=filename,
                            content_type=content_type.decode("latin-1"),
                        )
                    else:
                        file = None
                elif message_type == MultiPartMessage.PART_DATA:
                    if file is None:
                        data += message_bytes
                    else:
                        await file.write(message_bytes)
                elif message_type == MultiPartMessage.PART_END:
                    if file is None:
                        items.append((field_name, _user_safe_decode(data, charset)))
                    else:
                        await file.seek(0)
                        items.append((field_name, file))
                elif message_type == MultiPartMessage.END:
                    pass

        parser.finalize()
        return FormData(items)