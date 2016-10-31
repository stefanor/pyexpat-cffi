#!/usr/bin/env python

from cffi import FFI
ffibuilder = FFI()

ffibuilder.set_source('pyexpat._expat',
"""
#include <expat.h>
""", libraries=['expat'])

ffibuilder.cdef("""
#define XML_PARAM_ENTITY_PARSING_NEVER ...
#define XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE ...
#define XML_PARAM_ENTITY_PARSING_ALWAYS ...
#define XML_TRUE ...
#define XML_FALSE ...
#define XML_STATUS_OK ...
#define XML_STATUS_ERROR ...

typedef unsigned char XML_Bool;

enum XML_Content_Type {
  XML_CTYPE_EMPTY,
  XML_CTYPE_ANY,
  XML_CTYPE_MIXED,
  XML_CTYPE_NAME,
  XML_CTYPE_CHOICE,
  XML_CTYPE_SEQ,
  ...
};

enum XML_Content_Quant {
  XML_CQUANT_NONE,
  XML_CQUANT_OPT,
  XML_CQUANT_REP,
  XML_CQUANT_PLUS,
  ...
};

enum XML_Error {
  XML_ERROR_NO_MEMORY,
  XML_ERROR_SYNTAX,
  XML_ERROR_NO_ELEMENTS,
  XML_ERROR_INVALID_TOKEN,
  XML_ERROR_UNCLOSED_TOKEN,
  XML_ERROR_PARTIAL_CHAR,
  XML_ERROR_TAG_MISMATCH,
  XML_ERROR_DUPLICATE_ATTRIBUTE,
  XML_ERROR_JUNK_AFTER_DOC_ELEMENT,
  XML_ERROR_PARAM_ENTITY_REF,
  XML_ERROR_UNDEFINED_ENTITY,
  XML_ERROR_RECURSIVE_ENTITY_REF,
  XML_ERROR_ASYNC_ENTITY,
  XML_ERROR_BAD_CHAR_REF,
  XML_ERROR_BINARY_ENTITY_REF,
  XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF,
  XML_ERROR_MISPLACED_XML_PI,
  XML_ERROR_UNKNOWN_ENCODING,
  XML_ERROR_INCORRECT_ENCODING,
  XML_ERROR_UNCLOSED_CDATA_SECTION,
  XML_ERROR_EXTERNAL_ENTITY_HANDLING,
  XML_ERROR_NOT_STANDALONE,
  XML_ERROR_UNEXPECTED_STATE,
  XML_ERROR_ENTITY_DECLARED_IN_PE,
  XML_ERROR_FEATURE_REQUIRES_XML_DTD,
  XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING,
  /* Added in Expat 1.95.7. */
  XML_ERROR_UNBOUND_PREFIX,
  /* Added in Expat 1.95.8. */
  XML_ERROR_UNDECLARING_PREFIX,
  XML_ERROR_INCOMPLETE_PE,
  XML_ERROR_XML_DECL,
  XML_ERROR_TEXT_DECL,
  XML_ERROR_PUBLICID,
  XML_ERROR_SUSPENDED,
  XML_ERROR_NOT_SUSPENDED,
  XML_ERROR_ABORTED,
  XML_ERROR_FINISHED,
  XML_ERROR_SUSPEND_PE,
  ...
};

typedef char XML_Char;
typedef int... XML_Index;
typedef int... XML_Size;

typedef struct {
  int major;
  int minor;
  int micro;
} XML_Expat_Version;

typedef struct {
  enum XML_FeatureEnum  feature;
  const char            *name;
  long int              value;
} XML_Feature;

typedef struct XML_cp XML_Content;
struct XML_cp {
  enum XML_Content_Type         type;
  enum XML_Content_Quant        quant;
  XML_Char *                    name;
  unsigned int                  numchildren;
  XML_Content *                 children;
};

typedef struct {
  int map[256];
  void *data;
  int (*convert)(void *data, const char *s);
  void (*release)(void *data);
} XML_Encoding;

struct XML_ParserStruct;
typedef struct XML_ParserStruct *XML_Parser;

const char *
XML_ErrorString(enum XML_Error code);

const char *
XML_ExpatVersion(void);

XML_Expat_Version
XML_ExpatVersionInfo(void);

XML_Parser
XML_ExternalEntityParserCreate(XML_Parser parser,
                               const XML_Char *context,
                               const XML_Char *encoding);

void
XML_FreeContentModel(XML_Parser parser, XML_Content *model);

XML_Size
XML_GetCurrentLineNumber(XML_Parser parser);

XML_Size
XML_GetCurrentColumnNumber(XML_Parser parser);

XML_Index
XML_GetCurrentByteIndex(XML_Parser parser);

enum XML_Error
XML_GetErrorCode(XML_Parser parser);

XML_Index
XML_GetErrorByteIndex(XML_Parser parser);

XML_Size
XML_GetErrorColumnNumber(XML_Parser parser);

XML_Size
XML_GetErrorLineNumber(XML_Parser parser);

const XML_Feature *
XML_GetFeatureList(void);

const XML_Char *
XML_GetBase(XML_Parser parser);

enum XML_Status
XML_SetBase(XML_Parser parser, const XML_Char *base);

const char *
XML_GetInputContext(XML_Parser parser,
                    int *offset,
                    int *size);

void *
XML_GetUserData(XML_Parser parser);

void
XML_SetUserData(XML_Parser parser, void *userData);

enum XML_Status
XML_Parse(XML_Parser parser, const char *s, int len, int isFinal);

XML_Parser
XML_ParserCreate(const char *encoding);

XML_Parser
XML_ParserCreateNS(const char *encoding, char namespaceSeparator);

void
XML_ParserFree(XML_Parser parser);

int
XML_SetParamEntityParsing(XML_Parser parser,
                          enum XML_ParamEntityParsing parsing);

void
XML_SetReturnNSTriplet(XML_Parser parser, int do_nst);

enum XML_Status
XML_StopParser(XML_Parser parser, XML_Bool resumable);

enum XML_Error
XML_UseForeignDTD(XML_Parser parser, XML_Bool useDTD);
""")

HANDLERS = {
    'ElementDeclHandler': ('const XML_Char *name, XML_Content *model', None),
    'AttlistDeclHandler': ('const XML_Char *elname, const XML_Char *attname, '
                           'const XML_Char *att_type, const XML_Char *dflt, '
                           'int isrequired', None),
    'XmlDeclHandler': ('const XML_Char *version, const XML_Char *encoding, '
                       'int standalone', None),
    'StartElementHandler': (
        'const XML_Char *name, const XML_Char **atts', None),
    'EndElementHandler': ('const XML_Char *name', None),
    'CharacterDataHandler': ('const XML_Char *s, int len', None),
    'ProcessingInstructionHandler': (
        'const XML_Char *target, const XML_Char *data', None),
    'CommentHandler': ('const XML_Char *data', None),
    'StartCdataSectionHandler': ('', None),
    'EndCdataSectionHandler': ('', None),
    'DefaultHandler': ('const XML_Char *s, int len', None),
    'DefaultHandlerExpand': ('const XML_Char *s, int len', None),
    'StartDoctypeDeclHandler': (
        'const XML_Char *doctypeName, const XML_Char *sysid, '
        'const XML_Char *pubid, int has_internal_subset', None),
    'EndDoctypeDeclHandler': ('', None),
    'EntityDeclHandler': (
        'const XML_Char *entityName, int is_parameter_entity, '
        'const XML_Char *value, int value_length, const XML_Char *base, '
        'const XML_Char *systemId, const XML_Char *publicId, '
        'const XML_Char *notationName', None),
    'UnparsedEntityDeclHandler': (
        'const XML_Char *entityName, const XML_Char *base, '
        'const XML_Char *systemId, const XML_Char *publicId, '
        'const XML_Char *notationName', None),
    'NotationDeclHandler': (
        'const XML_Char *notationName, const XML_Char *base, '
        'const XML_Char *systemId, const XML_Char *publicId', None),
    'StartNamespaceDeclHandler': (
        'const XML_Char *prefix, const XML_Char *uri', None),
    'EndNamespaceDeclHandler': ('const XML_Char *prefix', None),
    'NotStandaloneHandler': ('', ('returns_int',)),
    'ExternalEntityRefHandler': (
        'XML_Parser parser, const XML_Char *context, const XML_Char *base, '
        'const XML_Char *systemId, const XML_Char *publicId',
        ('returns_int', 'no_userdata')),
    'SkippedEntityHandler': (
        'const XML_Char *entityName, int is_parameter_entity', None),
    'UnknownEncodingHandler': (
        'void *encodingHandlerData, const XML_Char *name, XML_Encoding *info',
        ('returns_int', 'no_userdata', 'extra_handle')),
}
for name, (signature, quirks) in HANDLERS.items():
    if quirks:
        quirks = set(quirks)
    else:
        quirks = set()
    returns_int = 'returns_int' in quirks
    takes_userdata = 'no_userdata' not in quirks
    extra_handle = 'extra_handle' in quirks

    if takes_userdata:
        signature = ('void *userData, ' + signature).rstrip(', ')
    subst = {
        'name': name,
        'signature': signature,
        'retval': 'int' if returns_int else 'void',
        'extra_handle': ', void *handle' if extra_handle else '',
    }
    cdef = (
        'typedef %(retval)s (*XML_%(name)s)(%(signature)s);\n'
        'void XML_Set%(name)s(XML_Parser parser, XML_%(name)s handler'
        '%(extra_handle)s);\n'
        'extern "Python" %(retval)s my_%(name)s(%(signature)s);\n'
        % subst)
    ffibuilder.cdef(cdef)

if __name__ == '__main__':
    ffibuilder.compile(verbose=True)
