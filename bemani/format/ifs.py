import hashlib
import io
import os
import struct
from PIL import Image  # type: ignore
from typing import Dict, List, Tuple, Optional

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

    def __init__(self, data: bytes, decode_binxml: bool=False, decode_textures: bool=False) -> None:
        self.__files: Dict[str, bytes] = {}
        self.__texdata: Dict[str, Node] = {}
        self.__mappings: Dict[str, str] = {}
        self.__sizes: Dict[str, Tuple[int, int]] = {}
        self.__decode_binxml = decode_binxml
        self.__decode_textures = decode_textures
        self.__parse_file(data)

    def __fix_name(self, filename: str) -> str:
        if filename[0] == '_' and filename[1].isdigit():
            filename = filename[1:]
        filename = filename.replace('_E', '.')
        filename = filename.replace('__', '_')
        return filename

    def __parse_file(self, data: bytes) -> None:
        # Grab the magic values and make sure this is an IFS
        (signature, version, version_crc, pack_time, unpacked_header_size, data_index) = struct.unpack(
            '>IHHIII',
            data[0:20],
        )
        if signature != 0x6CAD8F89:
            raise Exception('Invalid IFS file!')
        if version ^ version_crc != 0xFFFF:
            raise Exception('Corrupt version in IFS file!')

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
            header = xenc.decode(
                b'<?xml encoding="ascii"?>' +
                data[header_offset:data_index].split(b'\0')[0]
            )

            if header is None:
                raise Exception('Invalid IFS file!')

        files: Dict[str, Tuple[int, int, int]] = {}

        if header.name != 'imgfs':
            raise Exception('Unknown IFS format!')

        def get_children(parent: str, node: Node) -> None:
            real_name = self.__fix_name(node.name)
            if node.data_type == '3s32':
                node_name = os.path.join(parent, real_name).replace('/imgfs/', '')
                files[node_name] = (node.value[0] + data_index, node.value[1], node.value[2])
            else:
                for subchild in node.children:
                    get_children(os.path.join(parent, "{}/".format(real_name)), subchild)

        get_children("/", header)

        for fn in files:
            (start, size, pack_time) = files[fn]
            filedata = data[start:(start + size)]
            self.__files[fn] = filedata

        if self.__decode_textures:
            # We must fix up the name of the textures since we're decoding them
            def fix_name(hashname: str) -> str:
                path = os.path.dirname(hashname)
                filename = os.path.basename(hashname)

                texlist = self.__get_texlist_for_file(hashname)

                if texlist is not None and texlist.name == 'texturelist':
                    for child in texlist.children:
                        if child.name != 'texture':
                            continue

                        textfmt = child.attribute('format')

                        for subchild in child.children:
                            if subchild.name != 'image':
                                continue
                            md5sum = hashlib.md5(subchild.attribute('name').encode(benc.encoding)).hexdigest()

                            if md5sum == filename:
                                if textfmt == "argb8888rev":
                                    name = '{}.png'.format(subchild.attribute('name'))
                                else:
                                    name = subchild.attribute('name')
                                newpath = os.path.join(path, name)

                                rect = subchild.child_value('imgrect')
                                if rect is not None:
                                    self.__mappings[newpath] = textfmt
                                    self.__sizes[newpath] = (
                                        (rect[1] - rect[0]) // 2,
                                        (rect[3] - rect[2]) // 2,
                                    )

                                return newpath

                return hashname

            self.__files = {fix_name(fn): self.__files[fn] for fn in self.__files}

    @property
    def filenames(self) -> List[str]:
        return [f for f in self.__files]

    def __get_texlist_for_file(self, filename: str) -> Optional[Node]:
        texlist = os.path.join(os.path.dirname(filename), 'texturelist.xml')
        if texlist != filename and texlist in self.__files:
            if texlist not in self.__texdata and texlist in self.__files:
                benc = BinaryEncoding()
                self.__texdata[texlist] = benc.decode(self.__files[texlist])

            return self.__texdata.get(texlist)
        return None

    def read_file(self, filename: str) -> bytes:
        # If this is a texture folder, first we need to grab the texturelist.xml file
        # to figure out if this is compressed or not.
        decompress = False
        texlist = self.__get_texlist_for_file(filename)
        if texlist is not None and texlist.name == 'texturelist':
            if texlist.attribute('compress') == 'avslz':
                # We should decompress!
                decompress = True

        filedata = self.__files[filename]
        if decompress:
            uncompressed_size, compressed_size = struct.unpack('>II', filedata[0:8])
            if len(filedata) == compressed_size + 8:
                lz77 = Lz77()
                filedata = lz77.decompress(filedata[8:])
            else:
                raise Exception('Unrecognized compression!')

        if self.__decode_binxml and os.path.splitext(filename)[1] == '.xml':
            benc = BinaryEncoding()
            filexml = benc.decode(filedata)
            if filexml is not None:
                filedata = str(filexml).encode('utf-8')

        if self.__decode_textures and filename in self.__mappings and filename in self.__sizes:
            fmt = self.__mappings.get(filename)
            wh = self.__sizes.get(filename)
            if fmt == "argb8888rev":
                if len(filedata) < (wh[0] * wh[1] * 4):
                    left = (wh[0] * wh[1] * 4) - len(filedata)
                    filedata = filedata + b'\x00' * left
                img = Image.frombytes('RGBA', wh, filedata, 'raw', 'BGRA')
                b = io.BytesIO()
                img.save(b, format='PNG')
                filedata = b.getvalue()

        return filedata
