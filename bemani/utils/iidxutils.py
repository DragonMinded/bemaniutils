import argparse

from bemani.format import IIDXMusicDB


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to patch a IIDX music database.")
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

    fp = open(args.infile, 'rb')
    data = fp.read()
    fp.close()

    db = IIDXMusicDB(data)
    if args.hide_leggendarias:
        for song in db.songs:
            if song.title[-1:] == '†' or (
                song.difficulties[0] == 0 and
                song.difficulties[1] == 0 and
                song.difficulties[2] == 12
            ):
                print('Patching \'{}\' to only appear in leggendaria folder!'.format(song.title))
                song.folder = 0x5C

    print('Generating new database file...')
    fp = open(args.outfile, 'wb')
    fp.write(db.get_new_db())
    fp.close()


if __name__ == '__main__':
    main()
