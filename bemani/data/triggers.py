from datetime import datetime
from discord_webhook import DiscordWebhook, DiscordEmbed  # type: ignore
from typing import Any, Dict

from bemani.common.constants import GameConstants, BroadcastConstants
from bemani.data.types import Song


class Triggers:
    """
    Class for broadcasting data to some outside service
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def __gameconst_to_series(self, game: str) -> str:
        return {
            GameConstants.BISHI_BASHI: 'Bishi Bashi',
            GameConstants.DANCE_EVOLUTION: 'Dance Evolution',
            GameConstants.DDR: 'Dance Dance Revolution',
            GameConstants.IIDX: 'Beatmania IIDX',
            GameConstants.JUBEAT: 'Jubeat',
            GameConstants.MUSECA: 'MÚSECA',
            GameConstants.POPN_MUSIC: 'Pop\'n Music',
            GameConstants.REFLEC_BEAT: 'Reflec Beat',
            GameConstants.SDVX: 'Sound Voltex',
        }.get(game, 'Unknown')

    def broadcast_score(self, data: Dict[BroadcastConstants, str], game: str, song: Song) -> None:
        # For now we only support discord
        if self.config.get('webhooks', {}).get('discord', {}).get(game, None) is not None:
            self.broadcast_score_discord(data, game, song)

    def broadcast_score_discord(self, data: Dict[BroadcastConstants, str], game: str, song: Song) -> None:
        if game == GameConstants.IIDX:
            now = datetime.now()

            webhook = DiscordWebhook(url=self.config['webhooks']['discord'][game])
            scoreembed = DiscordEmbed(title=f'New {self.__gameconst_to_series(game)} Score!', color='fbba08')
            scoreembed.set_footer(text=(now.strftime('Score was recorded on %m/%d/%y at %H:%M:%S')))

            # lets give it an author
            song_url = f"{self.config['server']['uri']}/{game}/topscores/{song.id}" if self.config['server']['uri'] is not None else None
            scoreembed.set_author(name=self.config['name'], url=song_url)
            for item, value in data.items():
                inline = True
                if item in {BroadcastConstants.DJ_NAME, BroadcastConstants.SONG_NAME, BroadcastConstants.ARTIST_NAME, BroadcastConstants.PLAY_STATS_HEADER}:
                    inline = False
                scoreembed.add_embed_field(name=item.value, value=value, inline=inline)
            webhook.add_embed(scoreembed)
            webhook.execute()
