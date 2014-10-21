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


class IDAEnv(Env):
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
    def __init__(self, ea, env=guess_env(), parent=None):
        #super(WPrimitive, self).__init__()
        self._env = env
        self._ea = ea
        self._parent = parent

    def value(self):
        return NotImplementedError()


class WNull(W, WPrimitive):
    def __init__(self, env=guess_env, parent=None):
        W.__init__(self)
        WPrimitive.__init__(self, 0, env, parent)


    def __len__(self):
        return 0

    def __str__(self):
        return "NULL"

    def __repr__(self):
        return "NULL"

    def value(self):
        return 0


def MakeWPrimitive(name, fmt, size, str_formatter=str):
    """
    type size: func(WPrimitive:self, int:ea) or int
    """
    def __init__(self, ea, env=guess_env(), parent=None):
        WPrimitive.__init__(self, ea, env=env, parent=parent)
        W.__init__(self)
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
        return "%s(ea=%s)" % (name, hex(self._ea))

    def value(self):
        return self._parse()

    return type(name,
               (WPrimitive, W, Struct),
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


class InvalidParamterException(ValueError):
    pass


class WString(WPrimitive, W, Struct):
    def __init__(self, ea, size=None, env=guess_env(), parent=None, decoder="UTF-8"):
        """
        param size: length in bytes,
          or path specifier for element containing size, relative to parent
        """
        WPrimitive.__init__(self, ea, env=env, parent=parent)
        W.__init__(self)
        Struct.__init__(self, ea, env=env)
        if size is None:
            raise InvalidParameterException()
        self._size = size
        self._decoder = decoder

    def _parse(self):
        return self.read_bytes(self._ea, len(self)).decode(self._decoder)

    def __len__(self):
        if isinstance(self._size, basestring):
            return self._parent.get(self._size)
        else:
            return self._size

    def __str__(self):
        return self._parse()

    def __repr__(self):
        return "WString(ea=%s)" % (hex(self._ea))

    def value(self):
        return self._parse()


def MakeSizedWString(size):
    """
    param size: size in bytes, or path specifier from parent to size element.
    """
    def __init__(self, ea, env=guess_env(), parent=None, decoder="UTF-8"):
        WString.__init__(self, ea, size, env=env, parent=parent, decoder=decoder)

    return type("SizedWString", (WString, ), {"__init__": __init__})


class ShouldntGetHereException(Exception):
    pass


class InvalidPathException(Exception):
    pass


# type name: str
# type offset: int
# type instance: W
# type len: int
WField = namedtuple("WField", ["name", "offset", "instance", "len"])


class WStruct(object):

    FIELD_STATE_NEW = 0
    FIELD_STATE_STARTED = 1
    FIELD_STATE_DONE = 2

    def __init__(self, ea, fields, env=guess_env(), parent=None):
        #super(WStruct, self).__init__()
        self._fields = fields
        self._env = env
        self._ea = ea
        self._parent = parent

        self._field_state = 0
        self._applied_fields = []
        self._fields_by_name = {}  # type: map(str, WField)
        self._fields_by_offset = {}  # type: map(int, WField)
        self._total_length = 0

    def _apply_fields(self):
        if self._field_state > WStruct.FIELD_STATE_NEW:
            return

        self._field_state = WStruct.FIELD_STATE_STARTED
        ea = self._ea
        self._total_length = 0
        for field_name, field_type in self._fields:
            field_instance = field_type(ea, env=self._env, parent=self)
            field_size = len(field_instance)
            field = WField(field_name, ea, field_instance, field_size)

            self._fields_by_name[field_name] = field
            self._fields_by_offset[ea] = field
            self._applied_fields.append(field)

            ea += field_size
            self._total_length += field_size

        self._field_state = WStruct.FIELD_STATE_DONE

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
        """
        Get the field identified by `name`.
        This will be a WStruct, or WPrimitive, so in the latter case, you'll
          probably want to call `.value()` on it to make use of the thing.
        """
        if self._field_state == WStruct.FIELD_STATE_NEW:
            self._apply_fields()

        if name == "^":
            return self._parent
        else:  # should be a field name
            return self._fields_by_name[name].instance

    def get(self, path, sep="."):
        """
        Get the (potentially nested) member identified by `path`.
        Use the `sep` term to split `path` and descend into nested structs.
        Use "^" to ascend into the parent/enclosing struct.
        """
        num_parts = path.count(sep) + 1

        if len(path) == 0:
            raise InvalidPathException()

        def split_ptr_name(s):
            """
            split "**something" into ("**", "something")
            raise InvalidPathException: if "something" is ""
            """
            ptrs = ""  # leading *s
            name = ""  # everything after leading *s

            for i, c in enumerate(s):
                if c == "*":
                    ptrs += "*"
                else:
                    name = s[i:]
                    break
            if len(name) == 0:
                raise InvalidPathException()
            return ptrs, name

        if num_parts == 1:
            # have: next_field
            # have: *next_field
            path_name = path.partition(sep)[0]

            if path_name[0] == "*":
                ptrs, real_path_name = split_ptr_name(path_name)
                field = self.get_value(real_path_name)
                return field.get(ptrs, sep=sep)
            else:
                field = self.get_value(path_name)

                if isinstance(field, (WPrimitive, WPointer)):
                    return field.value()
                elif isinstance(field, (WString)):
                    return str(field)
                else:
                    return field

        else:  # len(parts) > 1
            our_part, _, their_parts = path.partition(sep)

            if our_part[0] == "*":
                # have: *next.next_field
                # have: **next.next_field
                ptrs, real_path_name = split_ptr_name(our_part)
                field = self.get_value(real_path_name)
                # path: *.next_field
                # path: **.next_field
                return field.get(ptrs + "." + their_parts)
            else:
                # have: next.next_field
                field = self.get_value(our_part)
                if isinstance(field, WPrimitive):
                    raise IndexError("Field %s is primitive" % our_part)
                else:
                    # path: next_field
                    return field.get(their_parts, sep=sep)
        raise ShouldntGetHereException()

    def as_dict(self):
        """
        Get this (potentially nested) struct as an unordered dict.
        """
        self._apply_fields()
        ret = {}
        for field in self._applied_fields:
            if isinstance(field, WPrimitive):
                ret[field.name] = field.instance.value()
            else:
                ret[field.name] = field.as_dict()
        return ret

    def dump(self, indent=0):
        self._apply_fields()
        ret = []

        for field in self._applied_fields:
            if isinstance(field.instance, (WPrimitive)):
                ret.append("%s/* %s */ (%s) %s: %s\n" % (
                           "  " * indent,
                           hex(field.offset),
                           repr(field.instance),
                           field.name,
                           str(field.instance.value())))
            elif isinstance(field.instance, (WPointer)):
                if isinstance(field.instance.deref(), (WPrimitive)):
                    ret.append("%s/* %s */ *(%s) %s: %s\n" % (
                               "  " * indent,
                               hex(field.offset),
                               repr(field.instance.deref()),
                               field.name,
                               str(field.instance.deref().value())))
                else:
                    ret.append("%s/* %s */ (%s) %s: %s\n" %
                               ("  " * indent,
                               hex(field.offset),
                               repr(field.instance),
                               field.name,
                               hex(field.instance.value())))
                    ret.append(field.instance.deref().dump(indent + 1))

            else:
                ret.append("%s/* %s */ (%s) %s:\n" %
                           ("  " * indent,
                           hex(field.offset),
                           repr(field.instance),
                           field.name))
                ret.append(field.instance.dump(indent + 1))

        return "".join(ret)


def MakeWStruct(name, fields):
    """
    type fields: iterable of (str:name, W:type)
    """
    def __init__(self, ea, env=guess_env(), parent=None):
        # TODO: changed this
        #W.__init__(self)
        WStruct.__init__(self, ea, fields, env=env, parent=parent)

    methods = {"__init__": __init__}
    for field_name, field_type in fields:
        # for hints on closures and scoping
        # see: http://stackoverflow.com/questions/2295290/what-do-lambda-funct\
        #   ion-closures-capture-in-python/2295372#2295372
        methods["get_%s" % field_name] = \
                lambda self, field_name=field_name: self.get_value(field_name)

    # TODO: changed this heirarchy
    return type(name, (WStruct, ), methods)


class WPointer(W, Struct):
    def __init__(self, ea, env=guess_env(), parent=None):
        W.__init__(self)
        Struct.__init__(self, ea, env=env)
        self._env = env
        self._parent = parent


def PointerTo(target_type, base=0):
    """
    Pointer relative to `base`.
    So, if you have a relative pointer, provide `base`.
    If you have an absolute pointer, just use `Pointer(MyStruct(...))`
    type target_type: W class
    rtype: subclass of WPointer
    """
    def __init__(self, ea, env=guess_env(), parent=None):
        WPointer.__init__(self, ea, env, parent)

    def _parse(self):
        if self._env.get_arch_bits() == Env.ARCH_BITS_32:
            return self._unpack("<I", 4, self._ea)
        elif self._env.get_arch_bits() == Env.ARCH_BITS_64:
            return self._unpack("<Q", 8, self._ea)
        else:
            raise BadArchitectureException()

    def __len__(self):
        if self._env.get_arch_bits() == Env.ARCH_BITS_32:
            return 4
        elif self._env.get_arch_bits() == Env.ARCH_BITS_64:
            return 8
        else:
            raise BadArchitectureException()

    def __str__(self):
        return hex(self._parse())

    def __repr__(self):
        if base != 0:
            return "Pointer(to=%s, base=%s, ea=%s)" % (target_type.__name__,
                                                       hex(base),
                                                       hex(self._ea))
        else:
            return "Pointer(to=%s, ea=%s)" % (target_type.__name__, hex(self._ea))

    def deref(self):
        ea = self._parse()
        if ea == 0:
            g_logger.warning("Dereferencing NULL")
            return WNull(env=self._env, parent=self)

        return target_type(base + ea, env=self._env, parent=self)

    def value(self):
        return self._parse()

    def get(self, path, sep="."):
        if len(path) == 0:
            raise InvalidPathException()

        if path[0] not in set(["*", "^"]):
            raise InvalidPathException()

        if len(path) == 1:
            if isinstance(target_type, WPrimitive):
                return self.deref().value()
            else:
                return self.deref()
        elif path[0] == "^":
            if len(path) < 2 or path[1] != ".":
                raise InvalidPathException()
            return self._parent.get(path.partition(sep)[2])
        else:
            our_part = path[0]
            their_parts = path[1:]

            if their_parts[0] == sep:
                # path should have looked like: *.next_field
                # have to cleanup leading `sep`
                v = self.deref()
                if isinstance(v, WPrimitive):
                    return v.value()
                else:
                    return v.get(their_parts.lstrip(sep), sep=sep)
            elif their_parts[0] == "*":
                # path should have looked like: **.next_field
                return self.deref().get(their_parts)
            else:
                # path should have looked like: *next_field
                # invalid
                raise InvalidPathException()

        raise ShouldntGetHereException()

    return type("Pointer",
               (WPointer,),
               {"__init__": __init__,
                "_parse": _parse,
                "__len__": __len__,
                "__str__": __str__,
                "__repr__": __repr__,
                "get": get,
                "value": value,
                "deref": deref})


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

    g_logger.debug(ss.get_f1())
    g_logger.debug(str(ss.get_f1()))
    assert str(ss.get_f1()) == "0x0"
    assert str(ss.get_f2()) == "0x201"

    assert ss.get_f1().value() == 0x0
    assert ss.get("f1") == 0x0
    assert ss.get_f2().value() == 0x201
    assert ss.get("f2") == 0x201

    return True


def test_complex_struct():
    env = LocalEnv("\x00\x01\x02\x03\xAA\xAA\xAA\xAA")

    SimpleStruct = MakeWStruct("SimpleStruct",
                               (("f1", Uint8),
                                ("f2", Uint16)))
    ComplexStruct = MakeWStruct("ComplexStruct",
                                (("c1", Uint8),
                                 ("c2", SimpleStruct)))
    cs = ComplexStruct(0, env=env)

    assert str(cs.get_c1()) == "0x0"
    assert str(cs.get_c2().get_f1()) == "0x1"
    assert str(cs.get_c2().get_f2()) == "0x302"


    assert cs.get_c1().value() == 0x0
    assert cs.get("c1") == 0x0
    assert cs.get_c2().get_f1().value() == 0x1
    assert cs.get("c2.f1") == 0x1
    assert cs.get_c2().get_f2().value() == 0x302
    assert cs.get("c2.f2") == 0x302

    assert cs.get("c2.^.c1") == 0x0

    return True


def test_pointer():
    env = LocalEnv("\x04\x00\x00\x00\x00\x01\x02\x03")

    SimpleStruct = MakeWStruct("SimpleStruct",
                               (("f1", Uint8),
                                ("f2", Uint16)))

    PointerStruct = MakeWStruct("PointerStruct",
                                (("p1", PointerTo(SimpleStruct)),))

    ps = PointerStruct(0, env=env)

    assert str(ps.get_p1().deref().get_f1()) == "0x0"
    assert str(ps.get_p1().deref().get_f2()) == "0x201"

    assert ps.get_p1().deref().get_f1().value() == 0x0
    assert ps.get("*p1.f1") == 0x0
    assert ps.get_p1().deref().get_f2().value() == 0x201
    assert ps.get("*p1.f2") == 0x201

    pi = PointerTo(Uint32)(0, env=env)
    assert pi.deref().value() == 0x3020100

    return True


def test_string():
    env = LocalEnv("\x08\x00\x00\x00\x02\x00\x00\x00Hi\x02\x03")

    SimpleStringStruct = MakeWStruct("SimpleStringStruct",
                                     (("unused", Uint32),
                                      ("size", Uint32),
                                      ("string", MakeSizedWString("size"))))

    ss = SimpleStringStruct(0, env=env)

    assert ss.get("size") == 0x2
    assert ss.get("string") == u"Hi"

    PointerStringStruct = MakeWStruct("PointerStringStruct",
                                     (("pstring",
                                         PointerTo(MakeSizedWString("^.size"))),
                                      ("size", Uint32)))

    ps = PointerStringStruct(0, env=env)

    assert ps.get("size") == 0x2
    assert str(ps.get("*pstring")) == u"Hi"

    return True


GoAlg = MakeWStruct("GoAlg",
        (
            ("memequal", PointerTo(Uint8)),
            ("memprint", PointerTo(Uint8)),
            ("memcopy", PointerTo(Uint8)),
            ("memhash", PointerTo(Uint8))))


GoString = MakeWStruct("GoString",
        (
            ("pstring", PointerTo(MakeSizedWString("^.size"))),
            ("size", Uint64)))


# TODO
GoSlice = MakeWStruct("GoSlice",
        (
            ("f1", PointerTo(Uint8)),
            ("f2", Uint64)))
            #("f3", Uint64)))


GoUncommonType = MakeWStruct("GoUncommonType",
        (
            ("name", PointerTo(GoString)),
            ("pkgPath", PointerTo(GoString)),
            ("mhdr", GoSlice),
            ("m", PointerTo(Uint8))))  # TODO


GoType = MakeWStruct("GoType",
        (
            ("size", Uint64),
            ("hash", Uint32),
            ("_unused", Uint8),
            ("align", Uint8),
            ("fieldAlign", Uint8),
            ("kind", Uint8),
            ("alg", PointerTo(GoAlg)),
            ("gc", PointerTo(Uint8)),
            ("string", PointerTo(GoString)),
            ("x", PointerTo(GoUncommonType)),
            #("pointerType", PointerTo(GoType)),  # recursion doesn't work yet
            ("pointerType", PointerTo(Uint8)),
            ("zeroValue", PointerTo(Uint8))))


def do_tests():
    g_logger.info("u8 test: %s", test_u8())
    g_logger.info("u16 test: %s", test_u16())
    g_logger.info("simple struct test: %s", test_simple_struct())
    g_logger.info("complex struct test: %s", test_complex_struct())
    g_logger.info("pointer test: %s", test_pointer())
    g_logger.info("string test: %s", test_string())
    g_logger.info("all tests completed successfully")


def dump_type(env, ea):
    t = GoType(ea, env=env)
    g_logger.debug("name: %s, size: %s",
            t.get("*string.*pstring"),
            hex(t.get_size().value()))

    pointerType = None
    pointerType = GoType(t.get_pointerType().value(), env=env)

    g_logger.debug("ptr: %s, size: %s",
            pointerType.get("*string.*pstring"),
            hex(pointerType.get_size().value()))

    g_logger.debug("uncommon: name: %s, pkgPath: %s",
            t.get("*x.*name.*pstring"),
            t.get("*x.*pkgPath.*pstring"))


def markup_string(env, ea):
    t = GoString(ea, env=env)

    val = str(t.get("*pstring"))
    MakeComm(ea, str("String: %s" % (val)))

    tt = "string_" + val.replace("*", "ptr_")

    for field in t._applied_fields:
        idaapi.set_name(field.offset, tt + "_" + field.name)
        if len(field.instance) == 1:
            MakeByte(field.offset)
        if len(field.instance) == 2:
            MakeWord(field.offset)
        if len(field.instance) == 4:
            MakeDword(field.offset)
        if len(field.instance) == 8:
            MakeQword(field.offset)

    idaapi.set_name(ea, tt)


def markup_uncommon_type(env, ea):
    t = GoUncommonType(ea, env=env)

    type_name = str(t.get("*name.*pstring"))
    MakeComm(ea, str("UncommonType: %s" % (type_name)))

    tt = "uncommontype_" + type_name.replace("*", "ptr_")

    for field in t._applied_fields:
        idaapi.set_name(field.offset, tt + "_" + field.name)
        if len(field.instance) == 1:
            MakeByte(field.offset)
        if len(field.instance) == 2:
            MakeWord(field.offset)
        if len(field.instance) == 4:
            MakeDword(field.offset)
        if len(field.instance) == 8:
            MakeQword(field.offset)

    idaapi.set_name(ea, tt)

    try:
        markup_string(env, t.get_name().value())
    except:
        g_logger.info("failed to markup uncommon type name string")

    try:
        markup_string(env, t.get_pkgPath().value())
    except:
        g_logger.info("failed to markup uncommon type pkgPath string")


def markup_type(env, ea):
    t = GoType(ea, env=env)

    type_name = str(t.get("*string.*pstring"))
    MakeComm(ea, str("Type: %s" % (type_name)))

    tt = "type_" + type_name.replace("*", "ptr_")

    for field in t._applied_fields:
        idaapi.set_name(field.offset, tt + "_" + field.name)
        if len(field.instance) == 1:
            MakeByte(field.offset)
        if len(field.instance) == 2:
            MakeWord(field.offset)
        if len(field.instance) == 4:
            MakeDword(field.offset)
        if len(field.instance) == 8:
            MakeQword(field.offset)
    idaapi.set_name(ea, tt)

    try:
        markup_uncommon_type(env, t.get_x().value())
    except:
        g_logger.info("failed to markup uncommon type")

    try:
        markup_type(env, t.get_pointerType().value())
    except:
        g_logger.info("failed to markup ptr type")


def dump_this_type():
    dump_type(IDAEnv(), ScreenEA())


def main():
#    do_tests()
#    dump_this_type()
     markup_type(IDAEnv(), ScreenEA())


if __name__ == "__main__":
    main()

