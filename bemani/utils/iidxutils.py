import argparse

from bemani.format import IIDXMusicDB


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A utility to patch a IIDX music database."
    )
    parser.add_argument(
        "infile",
        help="Music DB to work with.",
        type=str,
    )
    parser.add_argument(
        "outfile",
        help="Music DB to overwrite.",
        type=str,
    )
    parser.add_argument(
        "--hide-leggendarias",
        help="Hide leggendarias in normal folders.",
        action="store_true",
    )
    args = parser.parse_args()

    rfp = open(args.infile, "rb")
    data = rfp.read()
    rfp.close()

    db = IIDXMusicDB(data)
    if args.hide_leggendarias:
        for song in db.songs:
            if song.title[-1:] == "†" or (
                song.difficulties[0] == 0
                and song.difficulties[1] == 0
                and song.difficulties[2] == 12
            ):
                print(f"Patching '{song.title}' to only appear in leggendaria folder!")
                song.folder = 0x5C

    print("Generating new database file...")
    wfp = open(args.outfile, "wb")
    wfp.write(db.get_new_db())
    wfp.close()


if __name__ == "__main__":
    main()
