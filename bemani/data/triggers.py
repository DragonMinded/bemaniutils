from bemani.common.constants import GameConstants
from bemani.data.types import Song
from typing import Any, Dict
from discord_webhook import DiscordWebhook, DiscordEmbed  # type: ignore
from datetime import datetime


class Triggers:
    """
    Class for broadcasting data to some outside service
    """
    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def broadcast_score(self, data: Dict[str, str], game: str, song: Song) -> None:
        # For now we only support discord
        if self.config.get('webhooks', {}).get('discord', {}).get(game, None) is not None:
            self.broadcast_score_discord(data, game, song)

    def broadcast_score_discord(self, data: Dict[str, str], game: str, song: Song) -> None:
        if game == GameConstants.IIDX:
            now = datetime.now()

            webhook = DiscordWebhook(url=self.config['webhooks']['discord'][game])
            scoreembed = DiscordEmbed(title=f'New {game} Score!', color='fbba08')
            scoreembed.set_footer(text=(now.strftime('Score was recorded on %m/%d/%y at %H:%M:%S')))

            # lets give it an author
            song_url = f"{self.config['server']['uri']}/{game}/topscores/{song.id}" if self.config['server']['uri'] is not None else None
            scoreembed.set_author(name=self.config['name'], url=song_url)
            for item in data:
                inline = True
                if item in ['DJ Name', 'Song', 'Artist', 'Play Stats']:
                    inline = False
                scoreembed.add_embed_field(name=item, value=data[item], inline=inline)
            webhook.add_embed(scoreembed)
            webhook.execute()
