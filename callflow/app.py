# -*- coding: utf-8 -*-

import os
import sys
from datetime import timedelta
import traceback
from itertools import chain
from functools import update_wrapper

from .web.routing import Router
from .web.exceptions import HTTPException, InternalServerError, MethodNotAllowed, BadRequest, RequestRedirect

from .web.request import Request
from .web.response import Response, make_response
from .web.utils import reraise, to_bytes, to_unicode
from .server import Server


class CallFlow(object):
    """The callflow object implements a WSGI application and acts as the central
    object.  Once it is created it will act as a central registry for
    the view functions, the URL rules,  and more.

    Usually you create a `CallFlow` instance in your main module or
    in the `__init__.py` file of your package like this:

        from callflow import CallFlow
        app = CallFlow()

    """


    def __init__(self, import_name=''):
        self.config = {}

        self.import_name = import_name

        #: A dictionary of all view functions registered.  The keys will
        #: be function names which are also used to generate URLs and
        #: the values are the function objects themselves.
        self.view_functions = {}

        #: A dictionary of all registered error handlers.  The key is `None`
        #: for error handlers active on the application, otherwise the key is
        #: the name of the blueprint.  Each key points to another dictionary
        #: where they key is the status code of the http exception.  The
        #: special key `None` points to a list of tuples where the first item
        #: is the class for the instance check and the second the error handler
        #: function.
        #:
        self.error_handler_spec = {None: {}}

        #: A dictionary with lists of functions that should be called at the
        #: beginning of the request.  The key of the dictionary is the name of
        #: the blueprint this function is active for, `None` for all requests.
        #: This can for example be used to open database connections or
        #: getting hold of the currently logged in user.
        self.before_request_funcs = {}

        #: A dictionary with lists of functions that should be called after
        #: each request.  The key of the dictionary is the name of the blueprint
        #: this function is active for, `None` for all requests.  This can for
        #: example be used to open database connections or getting hold of the
        #: currently logged in user.
        self.after_request_funcs = {}
        self.teardown_request_funcs = {}

        #: all the attached blueprints in a dictionary by name.  Blueprints
        #: can be attached multiple times so this dictionary does not tell
        #: you how often they got attached.
        self.blueprints = {}

        self.router = Router()
        self.server = Server()

    @property
    def name(self):
        """The name of the application.  This is usually the import name
        with the difference that it's guessed from the run file if the
        import name is main.
        """
        if self.import_name == '__main__':
            fn = getattr(sys.modules['__main__'], '__file__', None)
            return os.path.splitext(os.path.basename(fn))[0] if fn else '__main__'
        return self.import_name


    def run(self, host=None, port=None, debug=True, **options):
        """Runs the application on a local development server.
        Args:

          * host: the hostname to listen on. Set this to '0.0.0.0' to
                     have the server available externally as well. Defaults to
                     '127.0.0.1'.
          * port: the port of the webserver. Defaults to 5000 or the
                     port defined in the SERVER_NAME` config variable if
                     present.
        """
        if host is None:
            host = '127.0.0.1'
        if port is None:
            port = 3000
        if debug is not None:
            self.debug = bool(debug)
        self.server.host = host
        self.server.port = port
        self.server.run_forever()

    def register_blueprint(self, blueprint, **options):
        """Registers a blueprint on the application.
        """
        if blueprint.name in self.blueprints:
            assert self.blueprints[blueprint.name] is blueprint, \
                'A blueprint\'s name collision occurred between %r and ' \
                '%r.  Both share the same name "%s".  Blueprints that ' \
                'are created on the fly need unique names.' % \
                (blueprint, self.blueprints[blueprint.name], blueprint.name)
        else:
            self.blueprints[blueprint.name] = blueprint
        blueprint.register(self, options)

    def add_url_rule(self, rule, endpoint=None, view_func=None, methods=None, **options):
        """Connects a URL rule.  Works exactly like the `route`
        decorator.  If a view_func is provided it will be registered with the
        endpoint.

        Basically this example:

            @app.route('/')
            def index():
                pass

        Is equivalent to the following:

            def index():
                pass
            app.add_url_rule('/', 'index', index)

        If the view_func is not provided you will need to connect the endpoint
        to a view function like so:

            app.view_functions['index'] = index

        Internally `route` invokes `add_url_rule` so if you want
        to customize the behavior via subclassing you only need to change
        this method.

        For more information refer to `url-route-registrations`.

        Args:

          * rule : the URL rule as string
          * endpoint : the endpoint for the registered URL rule.
          * view_func: the function to call when serving a request to the
                    provided endpoint
          * options: methods is a list of methods this rule should be limited
                    to (`GET`, `POST` etc.).
        """
        if endpoint is None:
            endpoint = view_func.__name__

        # if the methods are not given and the view_func object knows its
        # methods we can use that instead.  If neither exists, we go with
        # a tuple of only `GET` as default.
        if methods is None:
            methods = getattr(view_func, 'methods', None) or ('GET',)
        methods = set(methods)

        # Methods that should always be added
        required_methods = set(getattr(view_func, 'required_methods', ()))

        # Add the required methods now.
        methods |= required_methods

        defaults = options.get('defaults') or {}

        self.router.add(rule, endpoint, methods=methods, defaults=defaults)
        if view_func is not None:
            old_func = self.view_functions.get(endpoint)
            if old_func is not None and old_func != view_func:
                raise AssertionError('View function mapping is overwriting an '
                                     'existing endpoint function: %s' % endpoint)
            self.view_functions[endpoint] = view_func

    def route(self, rule, **options):
        """A decorator that is used to register a view function for a
        given URL rule.  This does the same thing as `add_url_rule`
        but is intended for decorator usage:

            @app.route('/')
            def index():
                return 'Hello World'

        For more information refer to `url-route-registrations`.

        Args:

          * rule: the URL rule as string
          * endpoint: the endpoint for the registered URL rule.
        """
        def decorator(f):
            endpoint = options.pop('endpoint', None)
            methods = options.pop('methods', None)
            self.add_url_rule(rule, endpoint, f, methods, **options)
            return f
        return decorator

    def endpoint(self, endpoint):
        """A decorator to register a function as an endpoint.
        Example:

            @app.endpoint('example.endpoint')
            def example():
                return "example"
        Args:
            endpoint: the name of the endpoint
        """
        def decorator(f):
            self.view_functions[endpoint] = f
            return f
        return decorator

    def errorhandler(self, code_or_exception):
        """A decorator that is used to register a function give a given
        error code.  Example:

            @app.errorhandler(404)
            def page_not_found(error):
                return 'This page does not exist', 404

        You can also register handlers for arbitrary exceptions:

            @app.errorhandler(DatabaseError)
            def special_exception_handler(error):
                return 'Database connection failed', 500

        You can also register a function as error handler without using
        the `errorhandler` decorator.  The following example is
        equivalent to the one above:

            def page_not_found(error):
                return 'This page does not exist', 404
            app.error_handler_spec[None][404] = page_not_found

        Setting error handlers via assignments to `error_handler_spec`
        however is discouraged as it requires fiddling with nested dictionaries
        and the special case for arbitrary exception types.

        The first `None` refers to the active blueprint.  If the error
        handler should be application wide `None` shall be used.

        """
        def decorator(f):
            self._register_error_handler(None, code_or_exception, f)
            return f
        return decorator

    def register_error_handler(self, code_or_exception, f):
        """Alternative error attach function to the `errorhandler`
        decorator that is more straightforward to use for non decorator
        usage.
        """
        self._register_error_handler(None, code_or_exception, f)

    def _register_error_handler(self, key, code_or_exception, f):
        if isinstance(code_or_exception, HTTPException):
            code_or_exception = code_or_exception.code
        if isinstance(code_or_exception, int):
            assert code_or_exception != 500 or key is None, \
                'It is currently not possible to register a 500 internal ' \
                'server error on a per-blueprint level.'
            self.error_handler_spec.setdefault(key, {})[code_or_exception] = f
        else:
            self.error_handler_spec.setdefault(key, {}).setdefault(None, []) \
                .append((code_or_exception, f))

    def before_request(self, f):
        """Registers a function to run before each request."""
        self.before_request_funcs.setdefault(None, []).append(f)
        return f


    def after_request(self, f):
        """Register a function to be run after each request.  Your function
        must take one parameter, a `Response` object and return
        a new response object.

        """
        self.after_request_funcs.setdefault(None, []).insert(0, f)
        return f

    def teardown_request(self, f):
        """Register a function to be run at the end of each request,
        regardless of whether there was an exception or not.

        Generally teardown functions must take every necessary step to avoid
        that they will fail.  If they do execute code that might fail they
        will have to surround the execution of these code by try/except
        statements and log occurring errors.

        When a teardown function was called because of a exception it will
        be passed an error object.
        """
        self.teardown_request_funcs.setdefault(None, []).insert(0, f)
        return f


    def handle_http_exception(self, e):
        """Handles an HTTP exception.  By default this will invoke the
        registered error handlers and fall back to returning the
        exception as response.
        """
        handlers = self.error_handler_spec.get(request.blueprint)
        # Proxy exceptions don't have error codes.  We want to always return
        # those unchanged as errors
        if e.code is None:
            return e
        if handlers and e.code in handlers:
            handler = handlers[e.code]
        else:
            handler = self.error_handler_spec[None].get(e.code)
        if handler is None:
            return e
        return handler(e)

    def handle_user_exception(self, e):
        """This method is called whenever an exception occurs that should be
        handled.  A special case are `~.web.exception.HTTPException`\s which are forwarded by
        this function to the `handle_http_exception` method.  This
        function will either return a response value or reraise the
        exception with the same traceback.

        """
        exc_type, exc_value, tb = sys.exc_info()
        assert exc_value is e

        # ensure not to trash sys.exc_info() at that point in case someone
        # wants the traceback preserved in handle_http_exception.  Of course
        # we cannot prevent users from trashing it themselves in a custom
        # trap_http_exception method so that's their fault then.
        if isinstance(e, HTTPException):
            return self.handle_http_exception(e)

        blueprint_handlers = ()
        handlers = self.error_handler_spec.get(request.blueprint)
        if handlers is not None:
            blueprint_handlers = handlers.get(None, ())
        app_handlers = self.error_handler_spec[None].get(None, ())
        for typecheck, handler in chain(blueprint_handlers, app_handlers):
            if isinstance(e, typecheck):
                return handler(e)

        reraise(exc_type, exc_value, tb)

    def handle_exception(self, e):
        """Default exception handling that kicks in when an exception
        occurs that is not caught.  In debug mode the exception will
        be re-raised immediately, otherwise it is logged and the handler
        for a 500 internal server error is used.  If no such handler
        exists, a default 500 internal server error message is displayed.
        """
        exc_type, exc_value, tb = sys.exc_info()

        handler = self.error_handler_spec[None].get(500)

        self.log_exception((exc_type, exc_value, tb))
        if handler is None:
            return InternalServerError()
        return handler(e)

    def log_exception(self, exc_info):
        """Logs an exception.  This is called by `handle_exception`
        if debugging is disabled and right before the handler is called.
        The default implementation logs the exception as error on the
        `logger`.
        """
        logger.error('Exception on %s [%s]' % (
            request.path,
            request.method
        ), exc_info=exc_info)

    def full_dispatch_request(self, request):
        """Dispatches the request and on top of that performs request
        pre and postprocessing as well as HTTP exception catching and
        error handling.
        """
        try:
            req = request
            endpoint, view_args = self.router.match(to_unicode(req.environ['PATH_INFO']))
            req.endpoint, req.view_args = endpoint, view_args
            rv = self.preprocess_request(req)
            if rv is None:
                rv = self.view_functions[req.endpoint](**req.view_args)
        except Exception as e:
            logger.info('%s'%(traceback.format_exc()))
            rv = self.handle_user_exception(e)
        response = make_response(rv)
        response = self.process_response(req, response)
        return response

    def preprocess_request(self, request):
        """Called before the actual request dispatching and will
        call every as `before_request` decorated function.
        If any of these function returns a value it's handled as
        if it was the return value from the view and further
        request handling is stopped.
        """
        bp = request.blueprint
        funcs = self.before_request_funcs.get(None, ())
        if bp is not None and bp in self.before_request_funcs:
            funcs = chain(funcs, self.before_request_funcs[bp])
        for func in funcs:
            rv = func(request)
            if rv is not None:
                return rv

    def process_response(self, request, response):
        """Can be overridden in order to modify the response object
        before it's sent to the WSGI server.  By default this will
        call all the `after_request` decorated functions.

        Args:

          * response: a `Response` object.

        Returns:

          * a new response object or the same, has to be an
                 instance of `Response`.
        """
        bp = request.blueprint
        funcs = []
        if bp is not None and bp in self.after_request_funcs:
            funcs = chain(funcs, self.after_request_funcs[bp])
        if None in self.after_request_funcs:
            funcs = chain(funcs, self.after_request_funcs[None])
        for handler in funcs:
            response = handler(request, response)
        return response

    def do_teardown_request(self, request, exc=None):
        """Called after the actual request dispatching and will
        call every as `teardown_request` decorated function.
        """
        if exc is None:
            exc = sys.exc_info()[1]
        funcs = self.teardown_request_funcs.get(None, ())
        bp = request.blueprint
        if bp is not None and bp in self.teardown_request_funcs:
            funcs = chain(funcs, self.teardown_request_funcs[bp])
        for func in funcs:
            rv = func(request, exc)


    def wsgi_app(self, environ, start_response):
        """The actual WSGI application.  This is not implemented in
        `__call__` so that middlewares can be applied without losing a
        reference to the class.  So instead of doing this:

            app = MyMiddleware(app)

        It's a better idea to do this instead:

            app.wsgi_app = MyMiddleware(app.wsgi_app)

        Then you still have the original application object around and
        can continue to call methods on it.

        Args:

          * environ: a WSGI environment
          * start_response: a callable accepting a status code,
                               a list of headers and an optional
                               exception to start the response
        """
        req = Request(environ)
        error = None
        try:
            try:
                response = self.full_dispatch_request(req)
            except Exception as e:
                logger.info('%s'%(traceback.format_exc()))
                error = e
                response = make_response(self.handle_exception(e))
            return response(environ, start_response)
        finally:
            self.do_teardown_request(req, error)

    def __call__(self, environ, start_response):
        """Shortcut for `wsgi_app`."""
        return self.wsgi_app(environ, start_response)

    def __repr__(self):
        return '<%s %r>' % (
            self.__class__.__name__,
            self.name,
        )