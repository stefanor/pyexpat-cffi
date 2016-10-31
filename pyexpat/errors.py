"""Constants used to describe error conditions."""

__all__ = []


def populate():
    from _expat import ffi, lib
    for name, value in lib.__dict__.items():
        if name.startswith('XML_ERROR_'):
            c_str = lib.XML_ErrorString(value)
            globals()[name] = ffi.string(c_str)
            __all__.append(name)

populate()
