"""Microsoft RICH signature extraction lib.

Using the research found online (doc/richsign.htm) this library carves out the
rich data.


RICH Sig block definition
-------------------------

This is an example of a RICH signature block found in PE files built
by Visual Studios 6.0+::

   DanS
   ZeroPad - XorMask
   ZeroPad - XorMask
   ZeroPad - XorMask
   Data 1
   Data 2
    ...
   "Rich"
   XorMask
   Padding

"""

import os
import re
import struct
import sys

TYPE_MAP = {}
ID_MAP = {}


class NoRichException(Exception):
    """No RICH signature found."""


class ParseError(Exception):
    """Error parsing PE file."""


def _parse_mappings(data: bytes) -> dict:
    # 0x0000 Foo Bar
    return {
        int(ln.split(" ", 1)[0], 16): ln.split(" ", 1)[1].strip()
        for ln in data.splitlines()
        if ln.strip() and not ln.startswith("#")
    }


def load_mappings(
    type_file=os.path.join(os.path.dirname(__file__), "richid_comptypes.txt"),
    id_file=os.path.join(os.path.dirname(__file__), "richid_prodids.txt"),
):
    """Load external mappings for comptypes and prodids."""
    global TYPE_MAP, ID_MAP
    with open(type_file, "r") as tmp:
        TYPE_MAP = _parse_mappings(tmp.read())
    with open(id_file, "r") as tmp:
        ID_MAP = _parse_mappings(tmp.read())


# load default mapping files on import
load_mappings()


def parse(data: bytes):
    r"""Parse the rich signature out of data.

    Return a tuple of (bytemask, objlist).
    Example output:
       ('\xfe\xba\x15\xbd',
         [{'compid': 8242727, 'majver': 13, 'minver': 50727, 'refcount': 4},
          {'compid': 7194151, 'majver': 13, 'minver': 50727, 'refcount': 22},
          {'compid': 65536, 'majver': 1, 'minver': 0, 'refcount': 149},
          {'compid': 8111655, 'majver': 11, 'minver': 50727, 'refcount': 19},
          {'compid': 7259687, 'majver': 14, 'minver': 50727, 'refcount': 28},
          {'compid': 8177191, 'majver': 12, 'minver': 50727, 'refcount': 1},
          {'compid': 7915047, 'majver': 8, 'minver': 50727, 'refcount': 1}])
    """
    richdata = _get_richdata(data)
    bytemask = _get_bytemask(richdata)
    sigdata = _get_sigdata(richdata, bytemask)
    objlist = _build_objlist(sigdata)
    return (bytemask, objlist)


def _get_richdata(data: bytes) -> bytes:
    s = re.search(b"PE", data)
    if not s:
        raise Exception("No PE header found")
    richdata = data[0x80 : s.start()]
    return richdata


def _get_richzeropad(richdata: bytes) -> bytes:
    s = re.search(b"Rich", richdata)
    if not s:
        raise NoRichException("No Rich found")
    zeropad = richdata[s.end() + 4 :]
    return zeropad


def _get_bytemask(richdata: bytes) -> bytes:
    s = re.search(b"Rich", richdata)
    if not s:
        raise NoRichException("No Rich found")
    bytemask = richdata[s.end() : s.end() + 4]
    return bytemask


def _get_sigdata(richdata: bytes, bytemask: bytes) -> bytes:
    s = re.search(b"Rich", richdata)
    if not s:
        raise NoRichException("No Rich found")
    obsig = richdata[0 : s.start()]
    sigdata = [byte ^ bytemask[index % len(bytemask)] for (index, byte) in enumerate(obsig)]
    return bytes(sigdata)


def _build_objlist(sigdata: bytes) -> list[dict]:
    if not sigdata.startswith(b"DanS"):
        raise ParseError("No DanS found in Sig block - %s" % repr(sigdata))
    if not sigdata[4:16] == b"\x00" * 12:
        raise ParseError("Expected 12 0x00, got %s" % (repr(sigdata[4:16])))
    sobjlist = sigdata[16:]
    if len(sobjlist) % 8 != 0:
        raise ParseError("length (%d) of objlist not divisible by 8" % (len(sobjlist)))

    objlist = []
    for i in range(int(len(sobjlist) / 8)):
        index = i * 8
        compid = struct.unpack("I", sobjlist[index : index + 4])[0]
        minver = compid & 0xFFFF
        majver = (compid >> 16) & 0xF
        refcount = struct.unpack("I", sobjlist[index + 4 : index + 8])[0]
        prodid = compid & 0xFFFF
        typeid = (compid >> 16) & 0xFF

        obj = dict(
            compid=compid,
            minver=minver,
            majver=majver,
            typeid=typeid,
            prodid=prodid,
            refcount=refcount,
        )
        if typeid in TYPE_MAP:
            obj["entrytype"] = TYPE_MAP[typeid]
        if prodid in ID_MAP:
            obj["product"] = ID_MAP[prodid]
        objlist.append(obj)
    return objlist


def checksum(data: bytes) -> bytes:
    """Calculate the checksum across the PE file data.

    Checksum is a 32bit value calculated over the DOS Header and unobfuscated
    compid entries.  This becomes The XOR key used to obfuscate the Rich
    Header contents in the file.
    """
    bytemask, objlist = parse(data)
    # skip pe pointer
    buf = data[0:60] + b"\0\0\0\0" + data[64:0x80]

    # checksum start at header offset
    cs = 0x80
    # add each header byte roated by index
    for i, temp in enumerate(buf):
        if sys.version_info[0] < 3:
            temp = ord(temp)
        cs += (temp << (i % 32)) | (temp >> (32 - (i % 32))) & 0xFF
        cs &= 0xFFFFFFFF
    # add each compid rotated by the ref/obj count
    for r in objlist:
        cs += r["compid"] << r["refcount"] % 32 | r["compid"] >> (32 - (r["refcount"] % 32))
        cs &= 0xFFFFFFFF
    return struct.pack("<I", cs)


def checksum_valid(data: bytes) -> bool:
    """Return whether the calculated checksum matches the mask bytes."""
    bytemask, objlist = parse(data)
    return bytemask == checksum(data)
