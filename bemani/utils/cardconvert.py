import argparse

from bemani.common import CardCipher, CardCipherException


def main() -> None:
    parser = argparse.ArgumentParser(description="A utility to convert between card IDs and back-of-card characters.")
    parser.add_argument(
        "number",
        help="card ID or back-of-card characters to convert.",
        type=str,
    )
    args = parser.parse_args()

    try:
        print(CardCipher.decode(args.number))
    except CardCipherException:
        try:
            back = CardCipher.encode(args.number)
            print(" ".join([back[i : (i + 4)] for i in range(0, len(back), 4)]))
        except CardCipherException:
            print("Bad card ID or back-of-card characters!")


if __name__ == "__main__":
    main()
