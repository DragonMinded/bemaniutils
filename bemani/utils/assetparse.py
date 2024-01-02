# vim: set fileencoding=utf-8

import argparse
import os
import xml.etree.ElementTree as ET
from PIL import Image
from typing import Dict, Optional

from bemani.common import GameConstants, VersionConstants
from bemani.data import Config
from bemani.utils.config import load_config


class ImportJubeat:
    def __init__(self, config: Config, version: str, update: bool) -> None:
        actual_version = {
            "saucer": VersionConstants.JUBEAT_SAUCER,
            "saucer-fulfill": VersionConstants.JUBEAT_SAUCER_FULFILL,
            "prop": VersionConstants.JUBEAT_PROP,
            "qubell": VersionConstants.JUBEAT_QUBELL,
            "clan": VersionConstants.JUBEAT_CLAN,
            "festo": VersionConstants.JUBEAT_FESTO,
        }.get(version, -1)
        if actual_version in {
            VersionConstants.JUBEAT_PROP,
            VersionConstants.JUBEAT_QUBELL,
            VersionConstants.JUBEAT_CLAN,
            VersionConstants.JUBEAT_FESTO,
        }:
            self.version = actual_version
        else:
            raise Exception("Unsupported Jubeat version, expected one of the following: prop, qubell, clan, festo!")

        self.config = config
        self.update = update

    def import_assets(self, xml: str, assets: Optional[str]) -> None:
        if assets is None:
            raise Exception("Expect a valid asset directory when importing emblems!")

        with open(args.xml, "rb") as xmlhandle:
            xmldata = xmlhandle.read().decode("shift_jisx0213")
        root = ET.fromstring(xmldata)

        file_mapping: Dict[str, str] = {}
        for emblem in root.find("emblem_list"):
            emblem.find("texname").text = emblem.find("texname").text.replace(".tex", ".png")
            file_mapping[emblem.find("texname").text] = f'{emblem.find("index").text}.png'

        if not file_mapping:
            # This isn't an emblem XML!
            raise Exception("Expect a valid emblem-info.xml file!")

        if not self.config.assets.jubeat.emblems:
            # We don't have the output set!
            raise Exception("Expect a valid directory for emblems in config file!")

        # First, make the root directory structure.
        actual_output = os.path.join(self.config.assets.jubeat.emblems, f"{self.version}")
        os.makedirs(actual_output, exist_ok=True)

        for fileroot, _, files in os.walk(assets):
            for filename in files:
                filepath = os.path.join(fileroot, filename)
                outname = os.path.splitext(filename)[0]
                renamed = file_mapping.get(f"{outname}.png")
                if renamed is None:
                    print(f"No mapping for {filepath}, skipping!")
                    continue

                full_renamed = os.path.join(actual_output, renamed)

                if os.path.exists(full_renamed) and not self.update:
                    print(f"Skipping existing {full_renamed}!")
                    continue

                print(f"Converting {filepath} to {full_renamed}...")

                # This is the image parsing section. Basically raw pixel data starting on byte 34 of the tex file.
                rawData = open(filepath, "rb").read()
                imgSize = (512, 512)  # the image size
                img = Image.frombytes("RGBA", imgSize, rawData[0x34:])
                img.save(full_renamed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Import game assets from various game files")
    parser.add_argument(
        "--series",
        action="store",
        type=str,
        required=True,
        help="The game series we are importing.",
    )
    parser.add_argument(
        "--version",
        dest="version",
        action="store",
        type=str,
        required=True,
        help="The game version we are importing.",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Core configuration for determining the output location. Defaults to 'config.yaml'.",
    )
    parser.add_argument(
        "--update",
        dest="update",
        action="store_true",
        default=False,
        help="Overwrite data with updated values when it already exists.",
    )
    parser.add_argument(
        "--xml",
        dest="xml",
        action="store",
        type=str,
        help="The game XML file to read, for applicable games.",
    )
    parser.add_argument(
        "--assets",
        dest="assets",
        action="store",
        type=str,
        help="The game assets directory, for applicable games.",
    )
    args = parser.parse_args()

    # Load the config so we can put assets in the right directory.
    config = Config()
    load_config(args.config, config)

    series = None
    try:
        series = GameConstants(args.series)
    except ValueError:
        pass

    if series == GameConstants.JUBEAT:
        jubeat = ImportJubeat(config, args.version, args.update)

        if args.xml:
            jubeat.import_assets(args.xml, args.assets)
        else:
            raise Exception("No emblem-info.xml provided! Please provide a --xml option!")

    else:
        raise Exception("Unsupported game series!")
