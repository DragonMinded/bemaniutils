import hashlib
import io
import os
import struct
from PIL import Image
from typing import Callable, Dict, List, Optional, Tuple

from bemani.format.dxt import DXTBuffer
from bemani.protocol.binary import BinaryEncoding
from bemani.protocol.xml import XmlEncoding
from bemani.protocol.lz77 import Lz77
from bemani.protocol.node import Node


class IFS:
    """
    Best-effort utility for decoding the `.ifs` file format. There are better tools out
    there, but this was developed before their existence. This should work with most of
    the games out there including non-rhythm games that use this format.
    """

    def __init__(
        self,
        data: bytes,
        decode_binxml: bool = False,
        decode_textures: bool = False,
        keep_hex_names: bool = False,
        reference_loader: Optional[Callable[[str], Optional["IFS"]]] = None,
    ) -> None:
        self.__files: Dict[str, bytes] = {}
        self.__formats: Dict[str, str] = {}
        self.__compressed: Dict[str, bool] = {}
        self.__imgsize: Dict[str, Tuple[int, int, int, int]] = {}
        self.__uvsize: Dict[str, Tuple[int, int, int, int]] = {}
        self.__decode_binxml = decode_binxml
        self.__keep_hex_names = keep_hex_names
        self.__decode_textures = decode_textures
        self.__loader = reference_loader
        self.__parse_file(data)

    def __fix_name(self, filename: str) -> str:
        if filename[0] == "_" and filename[1].isdigit():
            filename = filename[1:]
        filename = filename.replace("_E", ".")
        filename = filename.replace("__", "_")
        return filename

    def __parse_file(self, data: bytes) -> None:
        # Grab the magic values and make sure this is an IFS
        (
            signature,
            version,
            version_crc,
            pack_time,
            unpacked_header_size,
            data_index,
        ) = struct.unpack(
            ">IHHIII",
            data[0:20],
        )
        if signature != 0x6CAD8F89:
            raise Exception("Invalid IFS file!")
        if version ^ version_crc != 0xFFFF:
            raise Exception("Corrupt version in IFS file!")

        if version == 1:
            # No header MD5
            header_offset = 20
        else:
            # Make room for header MD5, at byte offset 20-36
            header_offset = 36

        # First, try as binary
        benc = BinaryEncoding()
        header = benc.decode(data[header_offset:data_index])

        if header is None:
            # Now, try as XML
            xenc = XmlEncoding()
            header = xenc.decode(b'<?xml encoding="ascii"?>' + data[header_offset:data_index].split(b"\0")[0])

            if header is None:
                raise Exception("Invalid IFS file!")

        files: Dict[str, Tuple[int, int, int, Optional[str]]] = {}

        if header.name != "imgfs":
            raise Exception("Unknown IFS format!")

        # Grab any super-files that this file might reference.
        header_md5: Optional[int] = None
        header_size: Optional[int] = None
        supers: List[Tuple[str, bytes]] = [("__INVALID__", b"")]

        for child in header.children:
            if child.name == "_info_":
                header_md5 = child.child_value("md5")  # NOQA
                header_size = child.child_value("size")  # NOQA
            elif child.name == "_super_":
                super_name = child.value
                super_md5 = child.child_value("md5")
                if not isinstance(super_name, str) or not isinstance(super_md5, bytes):
                    raise Exception(f"Super definition {child} has invalid data!")
                supers.append((super_name, super_md5))

        def get_children(parent: str, node: Node) -> None:
            real_name = self.__fix_name(node.name)
            if node.data_type == "3s32":
                node_name = os.path.join(parent, real_name).replace(f"{os.sep}imgfs{os.sep}", "")
                ref = None
                for subnode in node.children:
                    if subnode.name == "i":
                        super_ref = subnode.value
                        if super_ref > 0 or super_ref < len(supers):
                            ref = supers[super_ref][0]
                        else:
                            ref = supers[0][0]

                files[node_name] = (
                    node.value[0] + data_index,
                    node.value[1],
                    node.value[2],
                    ref,
                )
            else:
                for subchild in node.children:
                    get_children(os.path.join(parent, f"{real_name}{os.sep}"), subchild)

        # Recursively walk the entire filesystem extracting files and their locations.
        get_children(os.sep, header)

        # Cache of other file data.
        otherdata: Dict[str, IFS] = {}

        for fn in files:
            (start, size, pack_time, external_file) = files[fn]
            if external_file is not None:
                if external_file not in otherdata:
                    if self.__loader is None:
                        ifsdata = None
                    else:
                        ifsdata = self.__loader(external_file)

                    if ifsdata is None:
                        raise Exception(f"Couldn't extract file data for {fn} referencing IFS file {external_file}!")
                    else:
                        otherdata[external_file] = ifsdata

                if fn in otherdata[external_file].filenames:
                    filedata = otherdata[external_file].read_file(fn)
                else:
                    raise Exception(f"{fn} not found in {external_file} IFS!")
            else:
                filedata = data[start : (start + size)]
                if len(filedata) != size:
                    raise Exception(f"Couldn't extract file data for {fn}!")
            self.__files[fn] = filedata

        # Now, find all of the index files that are available.
        for filename in list(self.__files.keys()):
            abs_filename = (os.sep if filename.startswith(os.sep) else "") + filename

            if abs_filename.endswith(f"{os.sep}texturelist.xml"):
                # This is a texture index.
                texdir = os.path.dirname(filename)

                benc = BinaryEncoding()
                texdata = benc.decode(self.__files[filename])

                if texdata is None:
                    # Now, try as XML
                    xenc = XmlEncoding()
                    encoding = "ascii"
                    texdata = xenc.decode(b'<?xml encoding="ascii"?>' + self.__files[filename])

                    if texdata is None:
                        continue
                else:
                    if benc.encoding is None:
                        raise Exception("Logic error, expected an encoding from binary decoder!")
                    encoding = benc.encoding

                if texdata.name != "texturelist":
                    raise Exception(f"Unexpected name {texdata.name} in texture list!")

                if texdata.attribute("compress") == "avslz":
                    compressed = True
                else:
                    compressed = False

                for child in texdata.children:
                    if child.name != "texture":
                        continue

                    textfmt = child.attribute("format")
                    if textfmt is None:
                        raise Exception(f"Texture {child} has no texture format!")

                    for subchild in child.children:
                        if subchild.name != "image":
                            continue
                        name = subchild.attribute("name")
                        if name is None:
                            raise Exception(f"Texture entry {subchild} has no name!")
                        if " " in name:
                            # Certain files that were corrupted on create or copy
                            # seem to have spaces in the name which shouldn't be
                            # allowed. Lob them off.
                            name = name[: name.find(" ")]
                        md5sum = hashlib.md5(name.encode(encoding)).hexdigest()
                        oldname = os.path.join(texdir, md5sum)
                        newname = os.path.join(texdir, name)

                        if oldname in self.__files:
                            supported = False
                            if self.__decode_textures:
                                if textfmt in ["argb8888rev", "dxt5"]:
                                    # This is a supported file to decode
                                    newname += ".png"
                                    supported = True

                            # Remove old index, update file to new index.
                            self.__files[newname] = self.__files[oldname]
                            if not self.__keep_hex_names:
                                del self.__files[oldname]

                            # Remember the attributes for this file so we can extract it later.
                            self.__compressed[newname] = compressed

                            if supported:
                                # Only pop down the format and sizes if we support extracting.
                                self.__formats[newname] = textfmt

                                rect = subchild.child_value("imgrect")
                                if rect is not None:
                                    self.__imgsize[newname] = (
                                        rect[0] // 2,
                                        rect[1] // 2,
                                        rect[2] // 2,
                                        rect[3] // 2,
                                    )
                                rect = subchild.child_value("uvrect")
                                if rect is not None:
                                    self.__uvsize[newname] = (
                                        rect[0] // 2,
                                        rect[1] // 2,
                                        rect[2] // 2,
                                        rect[3] // 2,
                                    )
            elif abs_filename.endswith(f"{os.sep}afplist.xml"):
                # This is a texture index.
                afpdir = os.path.dirname(filename)
                bsidir = os.path.join(afpdir, "bsi")
                geodir = os.path.join(os.path.dirname(afpdir), "geo")

                benc = BinaryEncoding()
                afpdata = benc.decode(self.__files[filename])

                if afpdata is None:
                    # Now, try as XML
                    xenc = XmlEncoding()
                    encoding = "ascii"
                    afpdata = xenc.decode(b'<?xml encoding="ascii"?>' + self.__files[filename])

                    if afpdata is None:
                        continue
                else:
                    if benc.encoding is None:
                        raise Exception("Logic error, expected an encoding from binary decoder!")
                    encoding = benc.encoding

                if afpdata.name != "afplist":
                    raise Exception(f"Unexpected name {afpdata.name} in afp list!")

                for child in afpdata.children:
                    if child.name != "afp":
                        continue

                    # First, fix up the afp files themselves.
                    name = child.attribute("name")
                    if name is None:
                        raise Exception("AFP entry {child} has no name!")
                    md5sum = hashlib.md5(name.encode(encoding)).hexdigest()

                    for fixdir in [afpdir, bsidir]:
                        oldname = os.path.join(fixdir, md5sum)
                        newname = os.path.join(fixdir, name)

                        if oldname in self.__files:
                            # Remove old index, update file to new index.
                            self.__files[newname] = self.__files[oldname]
                            if not self.__keep_hex_names:
                                del self.__files[oldname]

                    # Now, fix up the shape files as well.
                    geodata = child.child_value("geo")
                    if geodata is not None:
                        for geoid in geodata:
                            geoname = f"{name}_shape{geoid}"
                            md5sum = hashlib.md5(geoname.encode(encoding)).hexdigest()

                            oldname = os.path.join(geodir, md5sum)
                            newname = os.path.join(geodir, geoname)

                            if oldname in self.__files:
                                # Remove old index, update file to new index.
                                self.__files[newname] = self.__files[oldname]
                                if not self.__keep_hex_names:
                                    del self.__files[oldname]

    @property
    def filenames(self) -> List[str]:
        return [f for f in self.__files]

    def read_file(self, filename: str) -> bytes:
        # First, figure out if this file is stored compressed or not. If it is, decompress
        # it so that we have the raw data available to us.
        decompress = self.__compressed.get(filename, False)
        filedata = self.__files[filename]
        if decompress:
            uncompressed_size, compressed_size = struct.unpack(">II", filedata[0:8])
            if len(filedata) == compressed_size + 8:
                lz77 = Lz77()
                filedata = lz77.decompress(filedata[8:])
            else:
                filedata = filedata[8:] + filedata[0:8]

        if self.__decode_binxml and os.path.splitext(filename)[1] == ".xml":
            benc = BinaryEncoding()
            filexml = benc.decode(filedata)
            if filexml is not None:
                filedata = str(filexml).encode("utf-8")

        if (
            self.__decode_textures
            and filename in self.__formats
            and filename in self.__imgsize
            and filename in self.__uvsize
        ):
            fmt = self.__formats[filename]
            img = self.__imgsize[filename]
            crop = self.__uvsize[filename]

            # Decode the image data itself.
            width = img[1] - img[0]
            height = img[3] - img[2]

            if fmt == "argb8888rev":
                if len(filedata) < (width * height * 4):
                    left = (width * height * 4) - len(filedata)
                    filedata = filedata + b"\x00" * left
                png = Image.frombytes("RGBA", (width, height), filedata, "raw", "BGRA")
                png = png.crop(
                    (
                        crop[0] - img[0],
                        crop[2] - img[2],
                        crop[1] - img[0],
                        crop[3] - img[2],
                    )
                )
                b = io.BytesIO()
                png.save(b, format="PNG")
                filedata = b.getvalue()
            elif fmt == "dxt5":
                dxt = DXTBuffer(width, height)
                png = Image.frombuffer(
                    "RGBA",
                    (width, height),
                    dxt.DXT5Decompress(filedata, swap=True),
                    "raw",
                    "RGBA",
                    0,
                    1,
                )
                png = png.crop(
                    (
                        crop[0] - img[0],
                        crop[2] - img[2],
                        crop[1] - img[0],
                        crop[3] - img[2],
                    )
                )
                b = io.BytesIO()
                png.save(b, format="PNG")
                filedata = b.getvalue()

        return filedata
