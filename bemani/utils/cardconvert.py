import argparse

from bemani.common import CardCipher, CardCipherException


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to convert between card IDs and back-of-card characters.")
    parser.add_argument(
        "number",
        help="card ID or back-of-card characters to convert.",
        type=str,
    )
    args, unk = parser.parse_known_args()

    # Special case for if you put spaces in a card ID.
    card = args.number
    if len(unk) == 3 and all(len(v) == 4 for v in unk):
        card = args.number + "".join(unk)

    try:
        print(CardCipher.decode(card))
    except CardCipherException:
        try:
            back = CardCipher.encode(card)
            print(" ".join([back[i : (i + 4)] for i in range(0, len(back), 4)]))
        except CardCipherException:
            print("Bad card ID or back-of-card characters!")


if __name__ == "__main__":
    main()
