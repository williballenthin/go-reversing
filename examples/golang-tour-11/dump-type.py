import struct
import logging
from collections import namedtuple

logging.basicConfig(level=logging.DEBUG)
g_logger = logging.getLogger("dump-type")

try:
    import idaapi
    import idc
except ImportError:
    g_logger.warning("Failed to import IDA libs")



class Env(object):
    """
    Interface for static analysis environment APIs
    """
    ARCH_BITS_32 = 32
    ARCH_BITS_64 = 64
    ENV_TYPE_LOCAL = "local"

    def __init__(self):
        super(Env, self).__init__()

    def get_bytes(self, ea, size):
        """
        rtype: byte string
        """
        raise NotImplementedError()

    def get_arch_bits(self):
        """
        rtype: ARCH_BITS_32 or ARCH_BITS_64
        """
        raise NotImplementedError()


def IDAEnv(Env):
    def __init__(self):
        super(IDAEnv, self).__init__()

    def get_bytes(self, ea, size):
        return GetManyBytes(ea, size)

    def get_arch_bits(self):
        if __EA64__:
            return Env.ARCH_BITS_64
        else:
            return Env.ARCH_BITS_32


class LocalEnv(Env):
    def __init__(self, buf, is_32=True):
        super(LocalEnv, self).__init__()
        self._buf = buf
        self._is_32 = is_32

    def get_bytes(self, ea, size):
        return self._buf[ea:ea+size]

    def get_arch_bits(self):
        if self._is_32:
            return Env.ARCH_BITS_32
        else:
            return Env.ARCH_BITS_64


def guess_env():
    try:
        a = __EA64__
        return IDAEnv()
    except:
        # test for Viv, etc.
        return None


class BadArchitectureException(Exception):
    pass


class Struct(object):
    def __init__(self, ea, env=guess_env()):
        #super(Struct, self).__init__()
        self._ea = ea

    def read_bytes(self, ea, size):
        return self._env.get_bytes(ea, size)

    def _unpack(self, pat, size, ea):
        return struct.unpack(pat, self.read_bytes(ea, size))[0]

    def read_uint8(self, ea):
        return self._unpack("<B", 1, ea)

    def read_uint16(self, ea):
        return self._unpack("<H", 2, ea)

    def read_uint32(self, ea):
        return self._unpack("<I", 4, ea)

    def read_uint64(self, ea):
        return self._unpack("<Q", 8, ea)

    def read_ptr(self, ea):
        if self._env.get_arch_bits() == Env.ARCH_BITS_32:
            return self.read_uint32(ea)
        elif self._env.get_arch_bits() == Env.ARCH_BITS_64:
            return self.read_uint64(ea)
        else:
            raise BadArchitectureException()

    def deref(self, ea):
        """
        alias
        """
        return self.read_ptr(ea)


class W(object):
    """
    interface for use in this W thing
    """
    def __len__(self):
        raise NotImplementedError()

    def __str__(self):
        return NotImplementedError()

    def __repr__(self):
        return NotImplementedError()


class WPrimitive(object):
    is_primitive = True

    def __init__(self, ea, env=guess_env()):
        #super(WPrimitive, self).__init__()
        self._env = env
        self._ea = ea

    def value(self):
        return NotImplementedError()


def MakeWPrimitive(name, fmt, size, str_formatter=str):
    """
    type size: func(WPrimitive, ea) or int
    """

    g_logger.debug("make: %s, '%s', %s, %s",
            name, fmt, size, str_formatter)

    def __init__(self, ea, env=guess_env()):
        W.__init__(self)
        WPrimitive.__init__(self, ea, env=env)
        Struct.__init__(self, ea, env=env)

    def _parse(self):
        return self._unpack(fmt, size, self._ea)

    def __len__(self):
        if hasattr(size, "__call__"):
            return size(self, self._ea)
        else:
            return size

    def __str__(self):
        return str_formatter(hex(self._parse()))

    def __repr__(self):
        return "%S(ea=%s)" % (name, hex(ea))

    def value(self):
        return self._parse()

    return type(name,
               (WPrimitive, Struct, W),
               {"__init__": __init__,
                "_parse": _parse,
                "__len__": __len__,
                "__str__": __str__,
                "__repr__": __repr__,
                "value": value})

Uint8 = MakeWPrimitive("Uint8", "<B", 1)
Uint16 = MakeWPrimitive("Uint16", "<H", 2)
Uint32 = MakeWPrimitive("Uint32", "<I", 4)
Uint64 = MakeWPrimitive("Uint64", "<Q", 8)



# type name: str
# type offset: int
# type instance: W
# type len: int
WField = namedtuple("WField", ["name", "offset", "instance", "len"])


class WStruct(object):
    is_primitive = False

    def __init__(self, ea, fields, env=guess_env()):
        #super(WStruct, self).__init__()
        self._fields = fields
        self._env = env
        self._ea = ea

        self._did_apply_fields = False
        self._applied_fields = []
        self._fields_by_name = {}  # type: map(str, WField)
        self._fields_by_offset = {}  # type: map(int, WField)
        self._total_length = 0

    def _apply_fields(self):
        if self._did_apply_fields:
            return

        ea = self._ea
        self._total_length = 0
        for field_name, field_type in self._fields:
            field_instance = field_type(ea, env=self._env)
            field_size = len(field_instance)
            field = WField(field_name, ea, field_instance, field_size)

            self._fields_by_name[field_name] = field
            self._fields_by_offset[ea] = field
            self._applied_fields.append(field)

            ea += field_size
            self._total_length += field_size

        self._did_apply_fields = True

    def __len__(self):
        self._apply_fields()
        return self._total_length

    def __str__(self):
        self._apply_fields()
        return "%s(%s)" % (self.__class__.__name__, self._fields)

    def __repr__(self):
        self._apply_fields()
        return "%s(%s)" % (self.__class__.__name__, self._fields)

    def get_value(self, name):
        self._apply_fields()
        return self._fields_by_name[name].instance

    def as_dict(self):
        self._apply_fields()
        ret = {}
        for field in self._applied_fields:
            if field.instance.is_primitive:
                ret[field.name] = field.instance.value()
            else:
                ret[field.name] = field.as_dict()
        return ret



def MakeWStruct(name, fields):
    """
    type fields: iterable of (str:name, W:type)
    """
    g_logger.debug("make struct: %s, %s", name, fields)

    def __init__(self, ea, env=guess_env()):
        WStruct.__init__(self, ea, fields, env=env)
        W.__init__(self)

    methods = {"__init__": __init__}
    for field_name, field_type in fields:
        # see: http://stackoverflow.com/questions/2295290/what-do-lambda-function-closures-capture-in-python/2295372#2295372
        # for hints on closures and scoping
        methods["get_%s" % field_name] = \
                lambda self, field_name=field_name: self.get_value(field_name)

    return type(name, (WStruct, W), methods)


def test_u8():
    env = LocalEnv("\x00\x01\x02\x03\xAA\xAA\xAA\xAA")

    assert str(Uint8(0, env=env)) == "0x0"
    assert str(Uint8(1, env=env)) == "0x1"
    assert str(Uint8(2, env=env)) == "0x2"
    assert str(Uint8(3, env=env)) == "0x3"

    assert Uint8(0, env=env).value() == 0x0
    assert Uint8(1, env=env).value() == 0x1
    assert Uint8(2, env=env).value() == 0x2
    assert Uint8(3, env=env).value() == 0x3

    return True


def test_u16():
    env = LocalEnv("\x00\x01\x02\x03\xAA\xAA\xAA\xAA")

    assert str(Uint16(0, env=env)) == "0x100"
    assert str(Uint16(1, env=env)) == "0x201"
    assert str(Uint16(2, env=env)) == "0x302"
    assert str(Uint16(3, env=env)) == "0xaa03"

    assert Uint16(0, env=env).value() == 0x100
    assert Uint16(1, env=env).value() == 0x201
    assert Uint16(2, env=env).value() == 0x302
    assert Uint16(3, env=env).value() == 0xAA03

    return True


def test_simple_struct():
    env = LocalEnv("\x00\x01\x02\x03\xAA\xAA\xAA\xAA")

    SimpleStruct = MakeWStruct("SimpleStruct",
                               (("f1", Uint8),
                                ("f2", Uint16)))
    ss = SimpleStruct(0, env=env)
    g_logger.debug("ss.f1: %s", ss.get_f1())
    g_logger.debug("ss.f2: %s", ss.get_f2())

    assert str(ss.get_f1()) == "0x0"
    assert str(ss.get_f2()) == "0x201"

    assert ss.get_f1().value() == 0x0
    assert ss.get_f2().value() == 0x201

    g_logger.debug("ss dict: %s", ss.as_dict())

    return True


def main():
    g_logger.info("u8 test: %s", test_u8())
    g_logger.info("u16 test: %s", test_u16())
    g_logger.info("simple struct test: %s", test_simple_struct())

if __name__ == "__main__":
    main()
