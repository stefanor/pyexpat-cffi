import itertools
import functools
import traceback
import string
import sys

from pyexpat import errors, model

from _expat import ffi, lib


__all__ = [
    'EXPAT_VERSION',
    'ErrorString',
    'ExpatError',
    'ParserCreate',
    'XMLParserType',
    'XML_PARAM_ENTITY_PARSING_ALWAYS',
    'XML_PARAM_ENTITY_PARSING_NEVER',
    'XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE',
    'error',
    'errors',
    'features',
    'model',
    'native_encoding',
    'version_info',
]


def _version_info():
    info = lib.XML_ExpatVersionInfo()
    return (info.major, info.minor, info.micro)


version_info = _version_info()
EXPAT_VERSION = ffi.string(lib.XML_ExpatVersion())
__version__ = sys.version.split()[0]

# When Expat supports some way of figuring out how it was
# compiled, this should check and set native_encoding
# appropriately.
native_encoding = 'UTF-8'

# Explicitly passing None means no interning is desired.
# Not passing anything means that a new dictionary is used.
INTERN_NEWDICT = object()

def _features():
    features = []
    f = lib.XML_GetFeatureList()
    for i in itertools.count():
        if f[i].feature == 0:
            break
        features.append((ffi.string(f[i].name), f[i].value))
    return features


features = _features()

XML_PARAM_ENTITY_PARSING_NEVER = lib.XML_PARAM_ENTITY_PARSING_NEVER
XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE = \
    lib.XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE
XML_PARAM_ENTITY_PARSING_ALWAYS = lib.XML_PARAM_ENTITY_PARSING_ALWAYS


class XMLParserType(object):
    __slots__ = (
        'AttlistDeclHandler',
        'CharacterDataHandler',
        'CommentHandler',
        'DefaultHandler',
        'DefaultHandlerExpand',
        'ElementDeclHandler',
        'EndCdataSectionHandler',
        'EndDoctypeDeclHandler',
        'EndElementHandler',
        'EndNamespaceDeclHandler',
        'EntityDeclHandler',
        'ExternalEntityRefHandler',
        'NotStandaloneHandler',
        'NotationDeclHandler',
        'ProcessingInstructionHandler',
        'SkippedEntityHandler',
        'StartCdataSectionHandler',
        'StartDoctypeDeclHandler',
        'StartElementHandler',
        'StartNamespaceDeclHandler',
        'UnparsedEntityDeclHandler',
        'XmlDeclHandler',
        '_buffer',
        '_exc_info',
        '_intern',
        '_parser',
        '_userdata',
        'buffer_size',
        'buffer_text',
        'namespace_prefixes',
        'ordered_attributes',
        'returns_unicode',
        'specified_attributes',
    )

    def __init__(self, parser, intern=INTERN_NEWDICT):
        self._parser = parser
        self._userdata = ffi.new_handle(self)
        lib.XML_SetUserData(parser, self._userdata)
        lib.XML_SetUnknownEncodingHandler(
            parser, lib.my_UnknownEncodingHandler, self._userdata)

        self._exc_info = None

        self._buffer = None
        self.buffer_size = 8192
        self.buffer_text = False

        self.namespace_prefixes = False
        self.ordered_attributes = False
        self.returns_unicode = True
        self.specified_attributes = False

        if intern == INTERN_NEWDICT:
            intern = {}
        elif not isinstance(intern, dict):
            raise TypeError('intern must be a dictionary')
        self._intern = intern

    def __del__(self):
        lib.XML_ParserFree(self._parser)

    @property
    def buffer_used(self):
        if self._buffer is None:
            return 0
        return sum(len(entry) for entry in self._buffer)

    @property
    def intern(self):
        return self._intern

    def __setattr__(self, name, value):
        boolean_attributes = (
            'buffer_text',
            'ordered_attributes',
            'returns_unicode',
            'specified_attributes',
            'namespace_prefixes',
        )
        if name in boolean_attributes:
            value = bool(value)

        # We usually need to customise setting, not getting, so this is far
        # simpler than properties
        method = getattr(self, '_set_%s' % name, None)
        if method:
            method(value)

        if (name.endswith(('Handler', 'HandlerExpand'))
                and not hasattr(self, name)):
            callback = getattr(lib, 'my_%s' % name)
            register = getattr(lib, 'XML_Set%s' % name)
            register(self._parser, callback)

        super(XMLParserType, self).__setattr__(name, value)

    def _set_namespace_prefixes(self, value):
        lib.XML_SetReturnNSTriplet(self._parser, value)

    def _set_buffer_size(self, value):
        if not isinstance(value, int):
            raise TypeError('buffer_size must be an integer')
        if not value > 0:
            raise ValueError('buffer_size must be greater than zero')
        if self._buffer and self._buffer_size != value:
            self._flush()

    def _set_buffer_text(self, value):
        if value:
            self._buffer = []
        else:
            self._flush()
            self._buffer = None

    def _buffer_string(self, data):
        if self._buffer is None:
            return False
        if self.buffer_used + len(data) > self.buffer_size:
            self._flush()
            # handler might have changed; drop the rest on the floor
            # if there isn't a handler anymore
            if not getattr(self, 'CharacterDataHandler', None):
                return True
        if len(data) <= self.buffer_size:
            self._buffer.append(data)
            return True
        else:
            self._buffer = []
        return len(self._buffer) or 0

    def _flush(self):
        if not self._buffer:
            return
        data = ''.join(self._buffer)
        self._buffer = []
        if getattr(self, 'CharacterDataHandler', None):
            self.CharacterDataHandler(data)

    def _set_error(self, code):
        lineno = lib.XML_GetErrorLineNumber(self._parser)
        column = lib.XML_GetErrorColumnNumber(self._parser)
        err_string = ffi.string(lib.XML_ErrorString(code))
        message = '%s: line %i, column %i' % (err_string, lineno, column)
        e = ExpatError(message)
        e.code = code
        e.lineno = lineno
        e.offset = column
        raise e

    def _string(self, cdata, maxlen=-1, intern_=False):
        """Turn cdata (up to maxlen bytes) into a Python string.
        If we're in unicode mode, decode.
        If requested, intern the result.
        We can't really intern unicode strings with pure Python, but we can
        achieve the same result, quite easily.
        """
        str_ = ffi.string(cdata, maxlen)
        if intern_:
            str_ = intern(str_)
            if str_ in self._intern:
                return self._intern[str_]
        value = str_
        if self.returns_unicode:
            value = value.decode(native_encoding)
        if intern_:
            self._intern[str_] = value
        return value

    @property
    def CurrentByteIndex(self):
        return lib.XML_GetCurrentByteIndex(self._parser)

    @property
    def CurrentColumnNumber(self):
        return lib.XML_GetCurrentColumnNumber(self._parser)

    @property
    def CurrentLineNumber(self):
        return lib.XML_GetCurrentLineNumber(self._parser)

    @property
    def ErrorByteIndex(self):
        return lib.XML_GetErrorByteIndex(self._parser)

    @property
    def ErrorCode(self):
        return lib.XML_GetErrorCode(self._parser)

    @property
    def ErrorColumnNumber(self):
        return lib.XML_GetErrorColumnNumber(self._parser)

    @property
    def ErrorLineNumber(self):
        return lib.XML_GetErrorLineNumber(self._parser)

    def ExternalEntityParserCreate(self, context, encoding=None):
        """ExternalEntityParserCreate(context[, encoding])
        Create a parser for parsing an external entity based on the
        information passed to the ExternalEntityRefHandler.
        """
        if encoding is None:
            encoding = ffi.NULL

        child_parser = lib.XML_ExternalEntityParserCreate(
            self._parser, context, encoding)
        if not child_parser:
            raise MemoryError

        child = XMLParserType(child_parser, intern=self._intern)

        # Copy handlers from self
        for name in self.__slots__:
            if name.endswith(('Handler', 'HandlerExpand')):
                handler = getattr(self, name, None)
                if handler:
                    setattr(child, name, handler)

        child.ordered_attributes = self.ordered_attributes
        child.returns_unicode = self.returns_unicode
        child.specified_attributes = self.specified_attributes
        child.namespace_prefixes = self.namespace_prefixes

        return child

    def GetBase(self):
        """GetBase() -> url
        Return base URL string for the parser.
        """
        base = lib.XML_GetBase(self._parser)
        if base == ffi.NULL:
            return None
        return ffi.string(base)

    def GetInputContext(self):
        """GetInputContext() -> string
        Return the untranslated text of the input that caused the current
        event. If the event was generated by a large amount of text (such as a
        start tag for an element with many attributes), not all of the text may
        be available.
        """
        offset = ffi.new('int *')
        size = ffi.new('int *')
        context = lib.XML_GetInputContext(self._parser, offset, size)
        offset = offset[0]
        size = size[0]
        if context == ffi.NULL:
            return None
        return ffi.string(context[offset:size])

    def Parse(self, data, isfinal=False):
        """Parse(data[, isfinal])
        Parse XML data.  `isfinal' should be true at end of input.
        """
        res = lib.XML_Parse(self._parser, data, len(data), isfinal)
        if self._exc_info:
            e = self._exc_info
            self._exc_info = None
            raise e[0], e[1], e[2]
        if res == 0:
            raise self._set_error(lib.XML_GetErrorCode(self._parser))
        self._flush()
        return res

    def ParseFile(self, file):
        """ParseFile(file)
        Parse XML data from file-like object.
        """
        for block in iter(lambda: file.read(2048), ''):
            self.Parse(block)
        return self.Parse('', isfinal=True)

    def SetBase(self, base):
        """SetBase(base_url)
        Set the base URL for the parser.
        """
        if not lib.XML_SetBase(self._parser, base):
            raise MemoryError

    def SetParamEntityParsing(self, flag):
        """SetParamEntityParsing(flag) -> success
        Controls parsing of parameter entities (including the external DTD
        subset). Possible flag values are XML_PARAM_ENTITY_PARSING_NEVER,
        XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE and
        XML_PARAM_ENTITY_PARSING_ALWAYS. Returns true if setting the flag
        was successful.
        """
        lib.XML_SetParamEntityParsing(self._parser, bool(flag))

    def UseForeignDTD(self, flag=True):
        """UseForeignDTD([flag])
        Allows the application to provide an artificial external subset if one
        is not specified as part of the document instance.  This readily allows
        the use of a 'default' document type controlled by the application,
        while still getting the advantage of providing document type
        information to the parser.  'flag' defaults to True if not provided.
        """
        lib.XML_UseForeignDTD(self._parser, bool(flag))

    def UnknownEncodingHandler(self, name, info):
        all_bytes = string.maketrans('', '')
        translationmap = all_bytes.decode(name, 'replace')
        if len(translationmap) != 256:
            raise ValueError('multi-byte encodings are not supported')

        for i, c in enumerate(translationmap):
            if c == u'\ufffd':
                info.map[i] = -1
            else:
                info.map[i] = ord(c)
        info.data = ffi.NULL
        info.convert = ffi.NULL
        info.release = ffi.NULL
        return True


class ExpatError(Exception):
    pass


error = ExpatError


def ParserCreate(encoding=None, namespace_separator=None,
                 intern=INTERN_NEWDICT):
    """ParserCreate([encoding[, namespace_separator]]) -> parser
    Return a new XML parser object."""

    if encoding is None:
        encoding = ffi.NULL
    elif not isinstance(encoding, str):
        raise TypeError('ParserCreate() argument 1 must be string or None, '
                        'not %s' % type(encoding).__name__)

    if namespace_separator is None:
        xmlparser = lib.XML_ParserCreate(encoding)
    else:
        if namespace_separator == '':
            namespace_separator = '\0'
        if not isinstance(namespace_separator, str):
            raise TypeError(
                'ParserCreate() argument 2 must be string or None, not %s'
                % type(namespace_separator).__name__
            )
        if len(namespace_separator) != 1:
            raise ValueError(
                'namespace_separator must be at most one character, omitted, '
                'or None'
            )
        xmlparser = lib.XML_ParserCreateNS(encoding, namespace_separator)

    parser = XMLParserType(xmlparser, intern=intern)
    return parser


def ErrorString(errno):
    """ErrorString(errno) -> string
    Returns string error for given number."""
    return ffi.string(lib.XML_ErrorString(errno))


def convert_model(model):
    """Convert a XML_Content struct into python tuples"""
    children = []
    for i in range(model.numchildren):
        children.append(convert_model(model.children[i]))
    if model.name == ffi.NULL:
        name = None
    else:
        name = ffi.string(model.name)
    return (model.type, model.quant, name, tuple(children))


@ffi.def_extern()
def my_UnknownEncodingHandler(userdata, name, info):
    parser = ffi.from_handle(userdata)
    name = ffi.string(name)
    try:
        parser.UnknownEncodingHandler(name, info)
        return lib.XML_STATUS_OK
    except Exception as e:
        if not parser._exc_info:
            parser._exc_info = sys.exc_info()
        lib.XML_StopParser(parser._parser, lib.XML_FALSE)
    return lib.XML_STATUS_ERROR


def handler(buffers=False, error_response=None, first_arg_is_parser=False,
            not_interned=(), return_zero_if_None=False):
    def decorator(arg_preprocessor):
        assert arg_preprocessor.__name__.startswith('my_')
        name = arg_preprocessor.__name__[3:]

        @functools.wraps(arg_preprocessor)
        def wrapper(userdata, *args):
            if first_arg_is_parser:
                userdata = lib.XML_GetUserData(userdata)
            parser = ffi.from_handle(userdata)

            callback = getattr(parser, name)
            if not callback:
                return error_response

            preprocessed = arg_preprocessor(parser, *args)
            if preprocessed is not None:
                args = preprocessed

            def process_args(args):
                for i, arg in enumerate(args):
                    if arg == ffi.NULL:
                        yield None
                    elif isinstance(arg, ffi.CData):
                        yield parser._string(arg,
                                             intern_=i not in not_interned)
                    else:
                        yield arg

            args = tuple(process_args(args))

            if buffers:
                if parser._buffer_string(*args):
                    return
            else:
                parser._flush()

            try:
                r = callback(*args)
            except Exception as e:
                # don't override an existing exception
                if not parser._exc_info:
                    parser._exc_info = sys.exc_info()
                lib.XML_StopParser(parser._parser, lib.XML_FALSE)
                return error_response

            if return_zero_if_None and r is None:
                r = 0

            return r

        return ffi.def_extern()(wrapper)
    return decorator


# These functions just process argument lists. All the real work is done in
# @handler, above.

@handler(not_interned=(2, 3))
def my_AttlistDeclHandler(parser, elname, attname, type, default, required):
    pass

@handler(buffers=True)
def my_CharacterDataHandler(parser, data, data_len):
    data = parser._string(data, data_len)
    return (data,)

@handler(not_interned=(0,))
def my_CommentHandler(parser, data):
    pass

@handler()
def my_DefaultHandler(parser, data, data_len):
    data = parser._string(data, data_len)
    return (data,)

@handler()
def my_DefaultHandlerExpand(parser, data, data_len):
    data = parser._string(data, data_len)
    return (data,)

@handler()
def my_ElementDeclHandler(parser, name, c_model):
    model = convert_model(c_model)
    lib.XML_FreeContentModel(parser._parser, c_model)
    return (name, model)

@handler()
def my_EntityDeclHandler(parser, entityName, is_parameter_entity, value,
                         value_len, base, systemId, publicId, notationName):
    value = parser._string(value, value_len)
    return (entityName, is_parameter_entity, value, base, systemId, publicId,
            notationName)

@handler(error_response=0,
         first_arg_is_parser=True,
         return_zero_if_None=True)
def my_ExternalEntityRefHandler(parser, context, base, systemId, publicId):
    if context != ffi.NULL:
        context = ffi.string(context)
    return (context, base, systemId, publicId)

@handler(error_response=0)
def my_NotStandaloneHandler(parser):
    pass

@handler()
def my_NotationDeclHandler(parser, notationName, base, systemId, publicId):
    pass

@handler()
def my_ProcessingInstructionHandler(parser, target, data):
    pass

@handler()
def my_SkippedEntityHandler(parser, entityName, is_parameter_entity):
    pass

@handler(not_interned=(0, 1, 2))
def my_XmlDeclHandler(parser, version, encoding, standalone):
    pass

@handler()
def my_StartCdataSectionHandler(parser):
    pass

@handler()
def my_EndCdataSectionHandler(parser):
    pass

@handler()
def my_StartDoctypeDeclHandler(
        parser, doctypeName, systemId, publicId, has_internal_subset):
    pass

@handler()
def my_EndDoctypeDeclHandler(parser):
    pass

@handler()
def my_StartElementHandler(parser, name, attributes):
    if parser.specified_attributes:
        maxindex = lib.XML_GetSpecifiedAttributeCount(parser._parser)
    else:
        maxindex = 0
        while attributes[maxindex]:
            maxindex += 2
    attributes = [parser._string(attr) for attr in attributes[0:maxindex]]
    if not parser.ordered_attributes:
        attributes = dict(zip(attributes[::2], attributes[1::2]))
    return (name, attributes)

@handler()
def my_EndElementHandler(parser, name):
    pass

@handler()
def my_StartNamespaceDeclHandler(parser, prefix, uri):
    pass

@handler()
def my_EndNamespaceDeclHandler(parser, prefix):
    pass

@handler()
def my_UnparsedEntityDeclHandler(
        parser, entityName, base, systemId, publicId, notationName):
    pass
