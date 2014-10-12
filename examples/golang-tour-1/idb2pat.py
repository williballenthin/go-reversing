import logging
import binascii
from collections import namedtuple

import crc16

from idc import *
from idaapi import *

logging.basicConfig(level=logging.DEBUG)
g_logger = logging.getLogger("idb2pat")



class Config(namedtuple("Config", ["min_func_length", "pointer_size"])):
    def __new__(cls, min_func_length=6, pointer_size=4):
        return super(Config, cls).__new__(cls, min_func_length, pointer_size=4)


def get_func_at_ea(ea):
    for i in xrange(get_func_qty()):
        f = getn_func(i)
        if f.startEA == ea:
            return f
    return None


class BadAddressException(Exception):
    pass


def find_ref_loc(config, ea, ref):
    if ea == BADADDR:
        raise BadAddressException()
    if ref == BADADDR:
        raise BadAddressException()

    if isCode(getFlags(ea)):
        for i in xrange(ea, ea + get_item_end(ea) - config.pointer_size):
            if get_long(i) == ref:
                return i

    return BADADDR


class FuncTooShortException(Exception):
    pass


def make_func_sig(config, func):
    """
    type config: Config
    type func: idc.func_t
    """
    logger = logging.getLogger("idb2pat:make_func_sig")

    if func.endEA - func.startEA < config.min_func_length:
        logger.debug("too short")
        raise FuncTooShortException()

    ea = func.startEA
    publics = []  # type: idc.ea_t
    refs = {}  # type: dict(idc.ea_t, idc.ea_t)
    variable_bytes = {}  # type: dict(idc.ea_t, bool)

    while ea != BADADDR and ea < func.endEA:
        logger.debug("ea: %s %d", hex(ea), ea)

        if get_name(0, ea) != None:
            logger.debug("name")
            publics.append(ea)

        ref = get_first_dref_from(ea)
        if ref != BADADDR:
            logger.debug("data ref")
            ref_loc = find_ref_loc(config, ea, ref)
            if ref_loc != BADADDR:
                logger.debug("ref loc: %s", hex(ref_loc))
                for i in xrange(config.pointer_size):
                    logger.debug("variable %s", hex(ref_loc + i))
                    variable_bytes[ref_loc + i] = True
                refs[ref_loc] = ref

            ref = get_next_dref_from(ea, ref)
            if ref != BADADDR:
                logger.debug("data ref2")
                ref_loc = find_ref_loc(config, ea, ref)
                if ref_loc != BADADDR:
                    logger.debug("ref loc: %s", hex(ref_loc))
                    for i in xrange(config.pointer_size):
                        logger.debug("variable %s", hex(ref_loc + i))
                        variable_bytes[ref_loc + i] = True
                    refs[ref_loc] = ref
        else:
            # code ref
            ref = get_first_fcref_from(ea)
            if ref != BADADDR:
                logger.debug("code ref")
                if ref < func.startEA or ref >= func.endEA:
                    # code ref is outside function
                    ref_loc = find_ref_loc(config, ea, ref)
                    if BADADDR != ref_loc:
                        logger.debug("ref loc: %s", hex(ref_loc))
                        for i in xrange(config.pointer_size):
                            logger.debug("variable %s", hex(ref_loc + i))
                            variable_bytes[ref_loc + i] = True
                        refs[ref_loc] = ref

        ea = next_not_tail(ea)

    sig = ""
    for ea in xrange(func.startEA, min(func.startEA + 32, func.endEA)):
        if variable_bytes.get(ea, False) == True:
            sig += ".."
        else:
            sig += "%x" % (get_byte(ea))

    sig += ".." * (32 - len(sig))

    logger.debug("sig: %s", sig)

    crc_data = [0 for i in xrange(256)]
    for i in xrange(32, min(func.endEA - func.startEA, 255 + 32)):
        if variable_bytes.get(i, False) == True:
            break
        crc_data[i - 32] = get_byte(func.startEA + i)

    alen = i - 32

    crc = crc16.crc16xmodem("".join(map(chr, crc_data[:alen]))) &  0xFFFFFFFF

    logger.debug("alen: %s", hex(alen))

    logger.debug("crc: %s", hex(crc))

    logger.debug("len: %s", hex(min(func.endEA - func.startEA, 32)))


def main():
    print("hello")
    c = Config()
    start_ea = ScreenEA()
    if start_ea is None:
        g_logger.error("need to focus a function")
        return

    f = get_func_at_ea(start_ea)
    if f is None:
        g_logger.error("no func at ea")
        return

    sig = make_func_sig(c, f)


if __name__ == "__main__":
    main()
