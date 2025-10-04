import argparse
import sys
from typing import Any, Dict, Optional
import yaml

from bemani.client import ClientProtocol, BaseClient
from bemani.client.iidx import (
    IIDXTricoroClient,
    IIDXSpadaClient,
    IIDXPendualClient,
    IIDXCopulaClient,
    IIDXSinobuzClient,
    IIDXCannonBallersClient,
    IIDXRootageClient,
)
from bemani.client.jubeat import (
    JubeatSaucerClient,
    JubeatSaucerFulfillClient,
    JubeatPropClient,
    JubeatQubellClient,
    JubeatClanClient,
    JubeatFestoClient,
)
from bemani.client.popn import (
    PopnMusicTuneStreetClient,
    PopnMusicFantasiaClient,
    PopnMusicSunnyParkClient,
    PopnMusicLapistoriaClient,
    PopnMusicEclaleClient,
    PopnMusicUsaNekoClient,
    PopnMusicPeaceClient,
    PopnMusicKaimeiClient,
    PopnMusicUnilabClient,
)
from bemani.client.ddr import (
    DDRX2Client,
    DDRX3Client,
    DDR2013Client,
    DDR2014Client,
    DDRAceClient,
)
from bemani.client.sdvx import (
    SoundVoltexBoothClient,
    SoundVoltexInfiniteInfectionClient,
    SoundVoltexGravityWarsS1Client,
    SoundVoltexGravityWarsS2Client,
    SoundVoltexHeavenlyHavenClient,
)
from bemani.client.museca import (
    Museca1Client,
    Museca1PlusClient,
)
from bemani.client.reflec import (
    ReflecBeat,
    ReflecBeatLimelight,
    ReflecBeatColette,
    ReflecBeatGroovinUpper,
    ReflecBeatVolzza,
    ReflecBeatVolzza2,
)
from bemani.client.bishi import TheStarBishiBashiClient
from bemani.client.mga import MetalGearArcadeClient
from bemani.client.danevo import DanceEvolutionClient


def get_client(proto: ClientProtocol, pcbid: str, game: str, config: Dict[str, Any]) -> BaseClient:
    if game == "pnm-tune-street":
        return PopnMusicTuneStreetClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-fantasia":
        return PopnMusicFantasiaClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-sunny-park":
        return PopnMusicSunnyParkClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-lapistoria":
        return PopnMusicLapistoriaClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-eclale":
        return PopnMusicEclaleClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-usaneko":
        return PopnMusicUsaNekoClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-peace":
        return PopnMusicPeaceClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-kaimei":
        return PopnMusicKaimeiClient(
            proto,
            pcbid,
            config,
        )
    if game == "pnm-unilab":
        return PopnMusicUnilabClient(
            proto,
            pcbid,
            config,
        )
    if game == "jubeat-saucer":
        return JubeatSaucerClient(
            proto,
            pcbid,
            config,
        )
    if game == "jubeat-saucer-fulfill":
        return JubeatSaucerFulfillClient(
            proto,
            pcbid,
            config,
        )
    if game == "jubeat-prop":
        return JubeatPropClient(
            proto,
            pcbid,
            config,
        )
    if game == "jubeat-qubell":
        return JubeatQubellClient(
            proto,
            pcbid,
            config,
        )
    if game == "jubeat-clan":
        return JubeatClanClient(
            proto,
            pcbid,
            config,
        )
    if game == "jubeat-festo":
        return JubeatFestoClient(
            proto,
            pcbid,
            config,
        )
    if game == "iidx-rootage":
        return IIDXRootageClient(
            proto,
            pcbid,
            config,
        )
    if game == "iidx-cannonballers":
        return IIDXCannonBallersClient(
            proto,
            pcbid,
            config,
        )
    if game == "iidx-sinobuz":
        return IIDXSinobuzClient(
            proto,
            pcbid,
            config,
        )
    if game == "iidx-copula":
        return IIDXCopulaClient(
            proto,
            pcbid,
            config,
        )
    if game == "iidx-pendual":
        return IIDXPendualClient(
            proto,
            pcbid,
            config,
        )
    if game == "iidx-spada":
        return IIDXSpadaClient(
            proto,
            pcbid,
            config,
        )
    if game == "iidx-tricoro":
        return IIDXTricoroClient(
            proto,
            pcbid,
            config,
        )
    if game == "bishi":
        return TheStarBishiBashiClient(
            proto,
            pcbid,
            config,
        )
    if game == "ddr-x2":
        return DDRX2Client(
            proto,
            pcbid,
            config,
        )
    if game == "ddr-x3":
        return DDRX3Client(
            proto,
            pcbid,
            config,
        )
    if game == "ddr-2013":
        return DDR2013Client(
            proto,
            pcbid,
            config,
        )
    if game == "ddr-2014":
        return DDR2014Client(
            proto,
            pcbid,
            config,
        )
    if game == "ddr-ace":
        return DDRAceClient(
            proto,
            pcbid,
            config,
        )
    if game == "sdvx-booth":
        return SoundVoltexBoothClient(
            proto,
            pcbid,
            config,
        )
    if game == "sdvx-infinite-infection":
        return SoundVoltexInfiniteInfectionClient(
            proto,
            pcbid,
            config,
        )
    if game == "sdvx-gravity-wars-s1":
        return SoundVoltexGravityWarsS1Client(
            proto,
            pcbid,
            config,
        )
    if game == "sdvx-gravity-wars-s2":
        return SoundVoltexGravityWarsS2Client(
            proto,
            pcbid,
            config,
        )
    if game == "sdvx-heavenly-haven":
        return SoundVoltexHeavenlyHavenClient(
            proto,
            pcbid,
            config,
        )
    if game == "museca-1":
        return Museca1Client(
            proto,
            pcbid,
            config,
        )
    if game == "museca-1+1/2":
        return Museca1PlusClient(
            proto,
            pcbid,
            config,
        )
    if game == "reflec":
        return ReflecBeat(
            proto,
            pcbid,
            config,
        )
    if game == "reflec-limelight":
        return ReflecBeatLimelight(
            proto,
            pcbid,
            config,
        )
    if game == "reflec-colette":
        return ReflecBeatColette(
            proto,
            pcbid,
            config,
        )
    if game == "reflec-groovin-upper":
        return ReflecBeatGroovinUpper(
            proto,
            pcbid,
            config,
        )
    if game == "reflec-volzza":
        return ReflecBeatVolzza(
            proto,
            pcbid,
            config,
        )
    if game == "reflec-volzza2":
        return ReflecBeatVolzza2(
            proto,
            pcbid,
            config,
        )
    if game == "metal-gear-arcade":
        return MetalGearArcadeClient(
            proto,
            pcbid,
            config,
        )
    if game == "dance-evolution":
        return DanceEvolutionClient(
            proto,
            pcbid,
            config,
        )

    raise Exception(f"Unknown game {game}")


def mainloop(
    address: str,
    port: int,
    configfile: str,
    action: str,
    game: str,
    cardid: Optional[str],
    verbose: bool,
) -> None:
    games = {
        "pnm-tune-street": {
            "name": "Pop'n Music Tune Street",
            "model": "K39:J:B:A:2010122200",
            "old_profile_model": "J39:J:A:A",
            "avs": None,
        },
        "pnm-fantasia": {
            "name": "Pop'n Music Fantasia",
            "model": "L39:J:B:A:2012091900",
            "old_profile_model": "K39:J:A:A",
            "avs": "2.13.6 r4921",
        },
        "pnm-sunny-park": {
            "name": "Pop'n Music Sunny Park",
            "model": "M39:J:B:A:2014061900",
            "old_profile_model": "L39:J:A:A",
            "avs": "2.15.8 r6631",
        },
        "pnm-lapistoria": {
            "name": "Pop'n Music Lapistoria",
            "model": "M39:J:B:A:2015081900",
            "old_profile_model": "M39:J:B:A",
            "avs": "2.15.8 r6631",
        },
        "pnm-eclale": {
            "name": "Pop'n Music Eclale",
            "model": "M39:J:B:A:2016100500",
            "old_profile_model": "M39:J:B:A",
            "avs": "2.15.8 r6631",
        },
        "pnm-usaneko": {
            "name": "Pop'n Music Usagi to Neko to Shounen no Yume",
            "model": "M39:J:B:A:2018101500",
            "old_profile_model": "M39:J:B:A",
            "avs": "2.15.8 r6631",
        },
        "pnm-peace": {
            "name": "Pop'n Music peace",
            "model": "M39:J:B:A:2020092800",
            "old_profile_model": "M39:J:B:A",
            "avs": "2.15.8 r6631",
        },
        "pnm-kaimei": {
            "name": "Pop'n Music Kaimei riddles",
            "model": "M39:J:B:A:2022061300",
            "old_profile_model": "M39:J:B:A",
            "avs": "2.15.8 r6631",
        },
        "pnm-unilab": {
            "name": "Pop'n Music Unilab",
            "model": "M39:J:B:A:2024073100",
            "old_profile_model": "M39:J:B:A",
            "avs": "2.15.8 r6631",
        },
        "jubeat-saucer": {
            "name": "Jubeat Saucer",
            "model": "L44:J:A:A:2014012802",
            "avs": "2.15.8 r6631",
        },
        "jubeat-saucer-fulfill": {
            "name": "Jubeat Saucer Fulfill",
            "model": "L44:J:B:A:2014111800",
            "avs": "2.15.8 r6631",
        },
        "jubeat-prop": {
            "name": "Jubeat Prop",
            "model": "L44:J:B:A:2016031700",
            "avs": "2.15.8 r6631",
        },
        "jubeat-qubell": {
            "name": "Jubeat Qubell",
            "model": "L44:J:D:A:2016111400",
            "avs": "2.15.8 r6631",
        },
        "jubeat-clan": {
            "name": "Jubeat Clan",
            "model": "L44:J:E:A:2018070901",
            "avs": "2.17.3 r8311",
        },
        "jubeat-festo": {
            "name": "Jubeat Festo",
            "model": "L44:J:B:A:2022052400",
            "avs": "2.17.3 r8311",
        },
        "iidx-rootage": {
            "name": "Beatmania IIDX ROOTAGE",
            "model": "LDJ:J:A:A:2019090200",
            "avs": "2.17.0 r7883",
        },
        "iidx-cannonballers": {
            "name": "Beatmania IIDX CANNON BALLERS",
            "model": "LDJ:J:A:A:2018091900",
            "avs": "2.17.0 r7883",
        },
        "iidx-sinobuz": {
            "name": "Beatmania IIDX SINOBUZ",
            "model": "LDJ:J:A:A:2017082800",
            "avs": "2.16.1 r6901",
        },
        "iidx-copula": {
            "name": "Beatmania IIDX copula",
            "model": "LDJ:J:A:A:2016083100",
            "avs": "2.16.1 r6901",
        },
        "iidx-pendual": {
            "name": "Beatmania IIDX PENDUAL",
            "model": "LDJ:A:A:A:2015080500",
            "avs": "2.16.1 r6901",
        },
        "iidx-spada": {
            "name": "Beatmania IIDX SPADA",
            "model": "LDJ:A:A:A:2014071600",
            "avs": "2.16.1 r6901",
        },
        "iidx-tricoro": {
            "name": "Beatmania IIDX Tricoro",
            "model": "LDJ:J:A:A:2013090900",
            "avs": "2.15.8 r6631",
        },
        "bishi": {
            "name": "The★BishiBashi",
            "model": "IBB:A:A:A:2009092900",
            "avs": None,
        },
        "ddr-x2": {
            "name": "DanceDanceRevolution X2",
            "model": "JDX:J:A:A:2010111000",
            "avs": None,
        },
        "ddr-x3": {
            "name": "DanceDanceRevolution X3 VS 2ndMIX",
            "model": "KDX:J:A:A:2012112600",
            "avs": "2.13.6 r4921",
        },
        "ddr-2013": {
            "name": "DanceDanceRevolution (2013)",
            "model": "MDX:J:A:A:2014032700",
            "avs": "2.15.8 r6631",
        },
        "ddr-2014": {
            "name": "DanceDanceRevolution (2014)",
            "model": "MDX:A:A:A:2015122100",
            "avs": "2.15.8 r6631",
        },
        "ddr-ace": {
            "name": "DanceDanceRevolution A",
            "model": "MDX:U:D:A:2017121400",
            "avs": "2.15.8 r6631",
        },
        "sdvx-booth": {
            "name": "SOUND VOLTEX BOOTH",
            "model": "KFC:J:A:A:2013052900",
            "avs": "2.15.8 r6631",
        },
        "sdvx-infinite-infection": {
            "name": "SOUND VOLTEX II -infinite infection-",
            "model": "KFC:J:A:A:2014102200",
            "avs": "2.15.8 r6631",
        },
        "sdvx-gravity-wars-s1": {
            "name": "SOUND VOLTEX III GRAVITY WARS Season 1",
            "model": "KFC:J:A:A:2015111602",
            "avs": "2.15.8 r6631",
        },
        "sdvx-gravity-wars-s2": {
            "name": "SOUND VOLTEX III GRAVITY WARS Season 2",
            "model": "KFC:J:A:A:2016121900",
            "avs": "2.15.8 r6631",
        },
        "sdvx-heavenly-haven": {
            "name": "SOUND VOLTEX IV HEAVENLY HAVEN",
            "model": "KFC:J:A:A:2019020600",
            "avs": "2.15.8 r6631",
        },
        "museca-1": {
            "name": "MÚSECA",
            "model": "PIX:J:A:A:2016071300",
            "avs": "2.17.0 r7883",
        },
        "museca-1+1/2": {
            "name": "MÚSECA 1+1/2",
            "model": "PIX:J:A:A:2017042600",
            "avs": "2.17.0 r7883",
        },
        "reflec": {
            "name": "REFLEC BEAT",
            "model": "KBR:A:A:A:2011112300",
            "avs": None,
        },
        "reflec-limelight": {
            "name": "REFLEC BEAT limelight",
            "model": "LBR:A:A:A:2012082900",
            "avs": "2.13.6 r4921",
        },
        "reflec-colette": {
            "name": "REFLEC BEAT colette",
            "model": "MBR:J:A:A:2014011600",
            "avs": "2.15.8 r6631",
        },
        "reflec-groovin-upper": {
            "name": "REFLEC BEAT groovin'!! Upper",
            "model": "MBR:J:A:A:2015102100",
            "avs": "2.15.8 r6631",
        },
        "reflec-volzza": {
            "name": "REFLEC BEAT VOLZZA",
            "model": "MBR:J:A:A:2016030200",
            "avs": "2.15.8 r6631",
        },
        "reflec-volzza2": {
            "name": "REFLEC BEAT VOLZZA 2",
            "model": "MBR:J:A:A:2016100400",
            "avs": "2.15.8 r6631",
        },
        "metal-gear-arcade": {
            "name": "Metal Gear Arcade",
            "model": "I36:J:A:A:2011092900",
            "avs": None,
        },
        "dance-evolution": {
            "name": "Dance Evolution",
            "model": "KDM:J:B:A:2016080100",
            "avs": "2.15.5 r6251",
        },
    }
    if action == "list":
        for game in sorted([game for game in games]):
            print(f'{game} - {games[game]["name"]}')
        sys.exit(0)
    if action == "game":
        if game not in games:
            print(f"Unknown game {game}")
            sys.exit(2)

        config = yaml.safe_load(open(configfile))

        print(f'Emulating {games[game]["name"]}')
        emu = get_client(
            ClientProtocol(
                address,
                port,
                config["core"]["encryption"],
                config["core"]["compression"],
                verbose,
            ),
            config["core"]["pcbid"],
            game,
            games[game],
        )

        emu.verify(cardid)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="A utility to generate game-like traffic for testing an eAmusement server."
    )
    parser.add_argument("-p", "--port", help="Port to talk to. Defaults to 80", type=int, default=80)
    parser.add_argument(
        "-a",
        "--address",
        help="Address to talk to. Defaults to 127.0.0.1",
        type=str,
        default="127.0.0.1",
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Core configuration. Defaults to trafficgen.yaml",
        type=str,
        default="trafficgen.yaml",
    )
    parser.add_argument(
        "-g",
        "--game",
        help="The game that should be emulated. Should be one of the games returned by --list",
        type=str,
        default=None,
    )
    parser.add_argument("-l", "--list", help="List all known games and exit.", action="store_true")
    parser.add_argument(
        "-i",
        "--cardid",
        help="Use this card ID instead of a random one.",
        type=str,
        default=None,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Print packets that are sent/received.",
        action="store_true",
        default=False,
    )
    args = parser.parse_args()

    if args.list:
        action = "list"
        game = None
    elif args.game:
        action = "game"
        game = args.game
    else:
        print("Unknown action to perform. Please specify --game <game> or --list")
        sys.exit(1)

    game = {
        "pnm-19": "pnm-tune-street",
        "pnm-20": "pnm-fantasia",
        "pnm-21": "pnm-sunny-park",
        "pnm-22": "pnm-lapistoria",
        "pnm-23": "pnm-eclale",
        "pnm-24": "pnm-usaneko",
        "pnm-25": "pnm-peace",
        "pnm-26": "pnm-kaimei",
        "pnm-27": "pnm-unilab",
        "iidx-20": "iidx-tricoro",
        "iidx-21": "iidx-spada",
        "iidx-22": "iidx-pendual",
        "iidx-23": "iidx-copula",
        "iidx-24": "iidx-sinobuz",
        "iidx-25": "iidx-cannonballers",
        "iidx-26": "iidx-rootage",
        "jubeat-5": "jubeat-saucer",
        "jubeat-5+": "jubeat-saucer-fulfill",
        "jubeat-6": "jubeat-prop",
        "jubeat-7": "jubeat-qubell",
        "jubeat-8": "jubeat-clan",
        "jubeat-9": "jubeat-festo",
        "ddr-12": "ddr-x2",
        "ddr-13": "ddr-x3",
        "ddr-14": "ddr-2013",
        "ddr-15": "ddr-2014",
        "ddr-16": "ddr-ace",
        "sdvx-1": "sdvx-booth",
        "sdvx-2": "sdvx-infinite-infection",
        "sdvx-3s1": "sdvx-gravity-wars-s1",
        "sdvx-3s2": "sdvx-gravity-wars-s2",
        "sdvx-4": "sdvx-heavenly-haven",
        "reflec-1": "reflec",
        "reflec-2": "reflec-limelight",
        "reflec-3": "reflec-colette",
        "reflec-4": "reflec-groovin-upper",
        "reflec-5": "reflec-volzza",
        "reflec-6": "reflec-volzza2",
        "mga": "metal-gear-arcade",
        "danevo": "dance-evolution",
    }.get(game, game)

    mainloop(args.address, args.port, args.config, action, game, args.cardid, args.verbose)


if __name__ == "__main__":
    main()
