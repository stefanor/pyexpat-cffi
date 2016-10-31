"""Constants used to interpret content model information."""

__all__ = []


def populate():
    from _expat import lib
    for name, value in lib.__dict__.items():
        if name.startswith(('XML_CTYPE_', 'XML_CQUANT_')):
            globals()[name] = value
            __all__.append(name)

populate()
