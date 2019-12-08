The backend services component is responsible for parsing game requests
and generating an appropriate response. It is divided into a dispatch
layer and a series of folders each representing a game series. There is
also a data layer filled with database access functions. Each game
series knows how to dispatch a request to an appropriate game class
given a model string and the Node structure (as detailed in PROTOCOL).
Each game class inherits from the base backend class which provides common
functionality such as boot requests, PASELI, and card lookup routines.
Both the base backend class and the game classes use the data layer to
determine appropriate responses given a request.

A rough sketch of how the pieces fit together is as follows:

                      ------------
                      | Dispatch |
                      ------------
                           |
                           |
                           V
       --------     --------------     --------------
       | Base |<--->| Game Class |<--->| Data Class |
       --------     --------------     --------------

Dispatch is responsible for taking a tree of Node objects and determining
which game class should handle it. It will extract the modelstring and
root Node's name in order to determine which game and what request is
being made. It will extract the PCBID of the request and optionally compare
it against known PCBIDs if enforcing mode is enabled. If the PCBID is tied
to an arcade, it will look up the details of that arcade in order to allow
an operator to override PASELI settings. Then, it create a database connection
using the Data class and instantiates the appropriate game class with the
Data class and modelstring provided on instantiation. Then, it attempts to
call the `handle_<request>_<method>_request` method on the instantiated game
class. The <request> portion represents the name of the root Node object, and
the <method> portion represents the string method found as an attribute on the
root node. If that doesn't exist, it falls back to the `handle_<request>_request`
method. Some series prefer to handle everything in one request method, manually
examining the method, and some prefer to have individual methods per request
and method combination. If neither of these exists, then it is assumed that
the game does not handle this packet and an appropriate error is generated.

Under most circumstances, code has been copied forward to new games in a series
instead of made common. This is because games tend to subtly change their
expectations of the network protocol under the assumption that the player will
never go back to older versions of the game or server. A conscious decision was
made to copy-paste code instead of trying to refactor it to be common, specifically
to represent the reality that while the code appears identical/similar enough,
its really up to the game engineers how to implement and things are subtly different.
In some cases, a packet truly doesn't change across versions and in that case
game series will chose to factor out common code, but in many cases the choice was
made to sacrifice ease of maintainability for stability across versions.

All game classes should inherit from Base. It has several
`handle_<request>_request` handlers for basic functions such as PASELI, bootup,
and card lookup routines. Base assumes that `has_profile`, `get_profile`,
`put_profile`, and `bind_profile` are subclassed by any game wishing to provide
complex profile handling, but provides default handlers which should work for any
simple game. It also provides `get_play_statistics` and `update_play_statistics`
which all games should use during their respective profile fetch and save. Base
handles looking up a user's PASELI balance if the PCBID of the request is in an
arcade and that arcade is set to non-infinite PASELI.

Each game class is expected to have a few properties. The 'game' property should
be a string name and is used for all DB operations when referring to a game
series. The 'version' property should be an integer and is used for all DB
operations when referring to a specific version of a game. Game code is free to
choose what these values are set to, but currently all games use constants
defined in `bemani/common/constants.py` for easier sharing with the BEMAPI REST
server and the frontend. This is how Base can provide statistics, profile lookup
and card manager services without knowing anything about what game is subclassin
g it. Aside from that, games are free to handle packets in any way they see fit.

In general, the tables provided by the database are indexed document stores.
Most BEMANI games are implemented entirely client-side and simply expect the
server to return the data it sent to it on the last profile save. For that to
work, there are a few database abstractions in use across various games. The
'profile' table stores JSON data given a specific game, so it is appropriate
for game-specific data. The 'game_settings' table stores JSON data given
a game series, so it is appropriate for data that is consistent across an
entire series. Note that this does not include scores! The 'achievement' table
stores JSON data given a specific game, an identifier and an identifier type.
This table is perfect for item data such as unlocks or event progress. The
'score' table stores JSON given a game and song ID, as does the 'score_history'
table. Note that the song ID is an internal representation and translated
through the 'music' table. This is to allow game series to renumber their
songs while still keeping score history across versions. It also allows the
server to preserve scores across multiple versions of a game. Note that all above
tables are accessed through the Data class instead of directly creating SQL
in the game classes.

In some cases, we access a remote version of the Data classes instead of the
MySQL version directly. The remote version in turn contacts any remote BEMAPI
REST servers as well as the local database and then sums up the information before
returning it to the game layer. In this way, we support fetching scores and
rivaling across networks using the BEMAPI REST API in a manner that is virtually
transparent to individual game implementations. Crucially, it is not used in
the API implementation itself nor in the frontend, ensuring that both only
respond with data that is contained on this instance directly.
