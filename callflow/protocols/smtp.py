
import socket
import ssl
import traceback
from basepy.asynclog import logger

class TooManyBadCommandsException(Exception):
    pass


class ClientQuitException(Exception):
    pass


class MainTransactionResetException(Exception):
    pass


class MailSocket(object):
    """
    Port from stdlib smtpd used by Gevent
    """
    SMTP_COMMANDS = [
        'HELO', 'EHLO', 'MAIL', 'RCPT', 'RSET', 'HELP', 'NOOP', 'QUIT', 'DATA',
        'STARTTLS'
    ]

    def __init__(self,
                 socket,
                 addr,
                 tls_args={},
                 domain='stmp.domain.com',
                 data_size_limit=1024 * 1024 * 2):
        self.socket = socket
        self.addr = addr
        self.domain = domain
        self.recvbuf_size = 4096
        self.buffer = b''
        self.closed = False
        self.data_size_limit = data_size_limit
        self.tls_required = True if tls_args else False
        self.tls_args = tls_args
        self.write('220 %s SMTP service ready' % self.domain)
        logger.debug('SMTP channel initialized')

    # SMTP and ESMTP commands
    def handle_greeting(self, command, args, mail, using_tls=False):
        if not args:
            self.write('501 Syntax: %s hostname' % (command))
            return
        extended_smtp = True if command == 'EHLO' else False
        mail['extended_smtp'] = extended_smtp
        if extended_smtp:
            text = 'TLS' if using_tls else 'plain'
            self.write('250-%s on %s' % (self.domain, text))
            if self.tls_required and not using_tls:
                self.write('250-STARTTLS')
            if self.data_size_limit:
                self.write('250-SIZE %s' % (self.data_size_limit))
            self.write('250 HELP')
        else:
            self.write('250 %s' % (self.domain))

    def handle_NOOP(self, args, mail):
        if args:
            self.write('501 Syntax: NOOP')
        else:
            self.write('250 Ok')

    def handle_QUIT(self, args, mail):
        # args is ignored
        self.write('221 Bye')
        self.close()

    def handle_STARTTLS(self, args, mail):
        if args:
            self.write('501 Syntax: STARTTLS')
            return False
        self.write('220 Ready to start TLS')

        try:
            self.socket = ssl.wrap_socket(self.socket, **self.tls_args)
            return True
        except Exception as err:
            logger.error(err, exc_info=True)
            self.write('503 certificate is FAILED')
            self.close()
        return False

    # factored
    def getaddr(self, keyword, arg):
        address = None
        keylen = len(keyword)
        if arg[:keylen].upper() == keyword:
            address = arg[keylen:].strip()
            if not address:
                pass
            elif address[0] == '<' and address[-1] == '>':
                address = address[1:-1]
        return address or None

    def handle_MAIL(self, args, mail):
        address = self.getaddr('FROM:', args[0]) if args else None
        if not address:
            self.write('501 Syntax: MAIL FROM:<address>')
            return
        if 'from' in mail:
            self.write('503 Error: nested MAIL command')
            return
        mail['from'] = address
        self.write('250 Ok')

    def handle_RCPT(self, args, mail):
        if 'from' not in mail:
            self.write('503 Error: need MAIL command')
            return
        address = self.getaddr('TO:', args[0]) if args else None
        if not address:
            self.write('501 Syntax: RCPT TO: <address>')
            return
        to = mail.setdefault('to', [])
        to.append(address)
        self.write('250 Ok')

    def handle_RSET(self, args, mail):
        if args:
            self.write('501 Syntax: RSET')
            return
        # Resets the sender, recipients, and data, but not the greeting
        mail.pop('from', None)
        mail.pop('to', None)
        mail.pop('data', None)
        self.write('250 Ok')

    def handle_DATA(self, args, mail):
        if args:
            self.write('501 Syntax: DATA')
            return False
        self.terminator = b'\r\n.\r\n'
        self.write('354 End data with <CR><LF>.<CR><LF>')
        return True

    def handle_HELP(self, args, mail):
        if args:
            if args[0].upper() == 'ME':
                self.write(
                    '504 Go to https://tools.ietf.org/html/rfc821 for help')
            else:
                self.write('501 Syntax: HELP')
        else:
            self.write('214 no further help')

    def read_mail(self):
        mail = {}
        if not self.wait_greeting(mail):
            return None
        while 1:
            try:
                if 'from' not in mail:
                    command, args = self.wait_request(['MAIL'], mail)
                    self.handle_MAIL(args, mail)
                if 'to' not in mail:
                    command, args = self.wait_request(['RCPT'], mail)
                    self.handle_RCPT(args, mail)

                while 1:
                    command, args = self.wait_request(['RCPT', 'DATA'], mail)
                    if command is None or command == 'DATA':
                        break
                    self.handle_RCPT(args, mail)
                self.handle_DATA(args, mail)
                mail['data'] = self.read_to_terminator(terminator=b'\r\n.\r\n')
                self.write('250 Ok')

                command, args = self.wait_request(['QUIT'], mail)
                self.handle_QUIT(args, mail)
                return mail or None
            except MainTransactionResetException:
                continue
            except (ClientQuitException, TooManyBadCommandsException):
                return None
            except Exception:
                logger.error('TRACEBACK', traceback.format_exc())
                return None

    def wait_greeting(self, mail):
        try:
            command, args = self.wait_request(['HELO', 'EHLO'], mail)
            self.handle_greeting(command, args, mail)

            if self.tls_required:
                while 1:
                    command, args = self.wait_request(['STARTTLS'], mail)
                    if self.handle_STARTTLS(args, mail):
                        mail = {}
                        break

                command, args = self.wait_request(['EHLO'], mail)
                self.handle_greeting(command, args, mail, using_tls=True)
            return True
        except (ClientQuitException, TooManyBadCommandsException):
            return False
        except Exception:
            logger.traceback('TRACEBACK', traceback.format_exc())
            return False

    def wait_request(self, commands, mail, response=None, max_wrong_cmds=6):
        n = 0
        while 1:
            command, args = self.read_request()
            if not command:
                return (None, None)
            if command not in commands:
                n += 1
                if n > max_wrong_cmds:
                    self.close()
                    raise TooManyBadCommandsException()
                if command == 'NOOP':
                    self.handle_NOOP(args, mail)
                elif command == 'HELP':
                    self.handle_HELP(args, mail)
                elif command == 'QUIT':
                    self.handle_QUIT(args, mail)
                    raise ClientQuitException()
                elif command == 'RSET':
                    if (
                        'HELO' in commands
                        or 'EHLO' in commands
                        or 'STARTTLS' in commands
                    ):
                        self.write('503 Bad sequence of commands')
                    else:
                        self.handle_RSET(args, mail)
                        raise MainTransactionResetException()
                else:
                    text = response or '503 Bad sequence of commands'
                    self.write(text)
            else:
                return command, args

    def read_request(self):
        line = self.readline()
        if not line:
            return (None, None)
        else:
            request_line = to_str(line.strip())
            request_parts = request_line.split(' ')
            command = request_parts[0].upper()
            request_parts[0] = command
            if command not in self.SMTP_COMMANDS:
                raise ValueError('Unsupported command: %s' % command)
            return (command, request_parts[1:])

    def read(self):
        try:
            data = self.socket.recv(self.recvbuf_size)
            if len(data) == 0:
                # issues 2 TCP connect closed will send a 0 size pack
                self.close()
        except socket.error:
            self.close()
            return self.buffer

        self.buffer = self.buffer + data
        return self.buffer

    def readline(self):
        while 1:
            index = self.buffer.find(b'\r\n')
            if index > -1:
                line = self.buffer[:index + 2]
                self.buffer = self.buffer[index + 2:]
                return line
            else:
                if not self.closed:
                    self.read()
                else:
                    return None

    def read_to_terminator(self, terminator):
        terminator = to_bytes(terminator)
        termlen = len(terminator)
        while 1:
            index = self.buffer.find(terminator)
            if index > -1:
                data = self.buffer[:index + termlen]
                self.buffer = self.buffer[index + termlen:]
                return data
            else:
                if not self.closed:
                    self.read()
                else:
                    return None

    def readbytes(self, nbytes):
        while 1:
            if len(self.buffer) >= nbytes:
                data = self.buffer[:nbytes]
                self.buffer = self.buffer[nbytes:]
                return data
            else:
                if not self.closed:
                    self.read()
                else:
                    return None

    def write(self, text):
        if not self.closed:
            try:
                self.socket.sendall(b'%s\r\n' % to_bytes(text))
            except Exception:
                self.close()

    def close(self):
        if not self.socket.closed:
            logger.debug('CLOSED %s' % self.socket)
            self.socket.close()
        self.closed = True

class MailHandler(object):
    def __init__(self,
                 socket,
                 address,
                 application,
                 ssl_args,
                 domain,
                 data_size_limit=1024 * 1024 * 2):
        self.socket = socket
        self.address = address
        self.application = application
        self.ssl_args = ssl_args
        self.domain = domain
        self.data_size_limit = data_size_limit

    def handle(self):
        try:
            ms = MailSocket(
                self.socket,
                self.address,
                tls_args=self.ssl_args,
                data_size_limit=self.data_size_limit,
                domain=self.domain)
            mail = ms.read_mail()
            if not mail:
                ms.close()
                return
            if self.application:
                self.application(mail, ms.write)
        except Exception:
            logger.error('TRACEBACK', traceback.format_exc())


class MailServer(StreamServer):
    def __init__(self,
                 listener=('0.0.0.0', 25),
                 application=None,
                 data_size_limit=1024 * 1024 * 2,
                 **kwargs):
        self.handler_class = MailHandler
        self.data_size_limit = int(data_size_limit)
        self.application = application
        self.domain = kwargs.get('domain') or 'localhost'

        self.ssl_args = {}

        if 'keyfile' in kwargs:
            self.ssl_args = {
                'keyfile': kwargs['keyfile'],
                'certfile': kwargs['certfile'],
                'cert_reqs': kwargs.get('cert_reqs') or ssl.CERT_NONE,
                'ca_certs': kwargs.get('ca_certs')
            }

        super(MailServer, self).__init__(listener, self.handle)

    def handle(self, sock, addr):
        logger.debug('Incomming connection %s:%s', *addr[:2])
        handler = self.handler_class(sock, addr, self.application,
                                     self.ssl_args, self.domain,
                                     self.data_size_limit)
        handler.handle()
