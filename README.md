# Introduction

A collection of programs for working with various games in the BEMANI series. This
could be untangled quite a bit into various modules that provide simpler pieces.
However, this is how it ended up evolving over time. This repository includes
utilities for unpacking (and sometimes repacking) various file formats, emulating
network services for various games, utilities for sniffing, redirecting and
reconstructing network packets, utilities for gathering information about various
game music databases and associated tooling that makes developing the previous
utilities easier. It is meant to be a complete ecosystem for somebody looking to
provide hobby network services to themselves in order to preserve a particular era
of gaming that is no longer officially supported.

Thanks to Tau for the great writeup on the binary network format. Thanks to some
rando on stack overflow for RC4 code for Python. Thanks to some other rando on
stack overflow for sample sniffer code for Python. Thanks to Tau again for the
great logging in easerver to compare my original output to. Thanks to PKGINGO for
encouragement and well-received excitement about progress. Thanks to Sarah and Alice
for being good RE partners for several games, and sharing good finds. Thanks to
helvetica for helping with game RE and retweeting cute anime ladies onto my feed
every goddamn night.

## 2dxutils

A utility for unpacking and repacking `.2dx` audio container files. Can extract
RIFF WAV audio out of an existing `.2dx` file, update an existing file or create
a new file from scratch given some WAV files. This isn't the best utility and I
think there are more complete and more accurate programs out there. However, they
all lack source as far as I could tell, so I developed this. Run it like
`./2dxutils --help` to see help output and determine how to use this.

## afputils

Utilities for working with several animation formats found across a vast range
of games. This includes a TXP2 container parser and repacker, a GE2D shape parser
and an AFP/BSI parser. Together, they make a set of utilities that attempts to work
with AFP, the fork of SWF that handles animations in various games. This utility
is capable of rendering animations out of IFS and TXP2 files as well as providing
decompiled pseudocode for the flash-like bytecode found in many animation files. It
is also capable of unpacking and repacking TXP2 containers with new texture files.
Note that this format is based on SWF and thus very complicated. Therefore, it
is unlikely that these tools will correctly handle all animations from all games
that it encounters. Run it like `./afputils --help` to see help output and determine
how to use it.

## api

Development version of this repository's BEMAPI implementation. This serves as the
REST-like API layer for inter-network federation of scores, profiles and rivals.
Run it like `./api --help` to see help output and determine how to use this. Much
like "services" and "frontend", this should be pointed at the development version
of your services config file which holds information about the MySQL database that
this should connect to as well as what game series are supported. See
`config/server.yaml` for an example file that you can modify.

Do not use this utility to serve production traffic. Instead, see
`bemani/wsgi/api.wsgi` for a ready-to-go WSGI file that can be used with a Python
virtualenv containing this project and its dependencies, uWSGI and nginx. Note that
if you do not wish to make your network available for federation then this entire
service can be omitted.

## arcutils

A utility for unpacking `.arc` files. This does not currently repack files. However,
the format is so trivial that adding such a feature would be fairly easy. Run it
like `./arcutils --help` to see help output and determine how to use this.

## assetparse

A utility which takes a particular game's asset directory and converts files for use
on the frontend. This optionally enables things such as customization previews on the
frontend. Much like "read", this requires a properly setup config file which points
the frontend as well as this utility at the correct location to store converted
assets. See `config/server.yaml` for an example file that you can modify. Unlike "read",
this utility is entirely optional. However, if you do not convert assets for games that
you are running, you will miss out on preview graphics on the frontend. Run it like
`./assetparse --help` to see help output and determine how to use this.

## bemanishark

A wire sniffer that can decode eAmuse packets and print them. Run it on a computer
that can sniff traffic between an eAmusement server and a supported game and it will
spit out the requests and responses XML-formatted identically to the XML output in
the logs of "services". This works on both binary and XML traffic. Note that it does
not have the capability to sniff SSL-encrypted traffic, so don't even bother trying
to run this at an arcade with official support.

Run it like `sudo ./bemanishark` to invoke. Will run indefinitely until killed
(Ctrl-C will suffice). Run like `./bemanishark --help` for options. Without options,
it assumes you want to sniff port 80 for all addresses. Note that it doesn't support
the Base64 binary blob formats found in SN1 and 2. Note also that over time it will
start to lose packets. This is a bug that I never figured out, and it appears to be
the OS failing to send over some packets resulting in a failure to reassemble the
TCP stream.

This utility might be better if rewritten to be a plugin for Wireshark instead of
a standalone sniffing utility, but I don't have the time.

## binutils

A utility for unpacking raw binxml data (files that use the same encoding scheme
as the binary network protocol) to their XML representation. This is useful for
examining raw binary blobs or digging into unknown file formats that contain binxml.
Run it like `./binutils --help` to see help and learn how to use this.

## bootstrap

A utility for quickly bootstrapping a local setup's music database from an already
running BEMAPI-compatible server that has been set up for federation. This is better
documented in the below "Database Initialization" section. Note that this utility assumes
no omnimix support and will bootstrap only normal game databases. The BEMAPI federation
protocol does support omnimix, so if you are bootstrapping against a running instance
that has omnimix databases and you wish to support omnimixes as well, you can look at
the source to this and manually run commands for the games in question.

## cardconvert

A command-line utility for converting between card numbers written on the back of a
card and the card ID stored in the RFID of the card. Run it like `./cardconvert --help`
to see how to use this. This will sanitize input, so you can feed it card numbers
with or without spaces, and you can mix up 1 and I as well as 0 and O, and it will
properly handle decoding. This supports both new and old style e-Amusement cards but
does not support the cross-play network cards with five groups of digits on the back
of the card.

## dbutils

A command-line utility for working with the DB used by "api", "services" and "frontend".
This utility includes options for creating tables in a newly-created DB, granting and
revoking admin rights to the frontend, generating migration scripts for production DBs,
and upgrading production DBs based on previously created migration scripts. Its driven
by alembic under the hood. You will use `create` on initial setup to generate a working
MySQL database. If you change the schema in code, you can use this again with the `generate`
option to generate a migration script. Whenever you run an upgrade to your production
instance, you should run this against your production DB with the `upgrade` option to
bring your production DB up to sync with the code you are deploying. Run it like
`./dbutils --help` to see all options. The config file that this works on is the same
that is given to "api", "services" and "frontend".

## formatfiles

A simple wrapper frontend to black, the formatter used on this project. Running this will
auto-format all of the python code that might need formatting, leaving the rest out. When
submitting pull requests make sure to run this so that your code conforms to the style
used by this project! Run this like `./formatfiles` to fix up all files in the repository.

## frontend

Development version of a frontend server allowing for account and server administration
as well as score viewing and profile editing. Run it like `./frontend --help` to see
help output and determine how to use this. Much like "services" and "api", this should
be pointed at the development version of your services config file which holds
information about the MySQL database that this should connect to as well as what game
series are supported. See `config/server.yaml` for an example file that you can modify.

Do not use this utility to serve production traffic. Instead, see
`bemani/wsgi/api.wsgi` for a ready-to-go WSGI file that can be used with a Python
virtualenv containing this project and its dependencies, uWSGI and nginx. Note thati
this shares a config file with "services" and "api" but is independent, sharing state
with them using the production DB only.

## ifsutils

A mediocre utility that can extract `.ifs` files. This has a lot of baked in
assumptions and is not nearly as good as other open-source utilities for extracting
files. It also cannot repack files yet. This is included for posterity, and because
some bootstrapping code requires it in order to fully start a production server.
Run it like `./ifsutils --help` to see help output and learn how to use it.

## iidxutils

A utility for patching IIDX music database files. Note that this currently can only
apply a "hide leggendarias from normal folders" patch, although it would be trivial
to extend for other uses such as song renames, difficulty patches and other fixups.
Run it like `./iidxutils --help` to see help output and learn how to use it.

## jsx

A utility which takes the existing JSX files in the repository and compiles them to
raw JS files for you. This is offered purely as a way to serve JSX files in a
production setup from nginx or similar instead of compiling them on-the-fly when
they are requested. You can use this to lower cold-start load times of your frontend.
If you do not make use of this or you are running the developent version of "frontend"
then JSX files are compiled on-the-fly when they are requested by the browser. This
behavior makes fast iteration possible by treating JSX files the same way that the
"frontend" debug utility treats python source files but removes the ability for a
production webserver such as nginx to serve static files. Run it like `./jsx --help`
to see help output and learn how to use it.

## proxy

A utility to MITM a network session. Point a game at the port this listens on, and
point this at another network to see the packets flowing between the two. Takes care
of rewriting the facility message to MITM all messages. Has the ability to rewrite
a request/response on the fly which is not currently used except for facility rewriting.
Its possible that this could be used to on-the-fly patch packets coming back from a
network which you don't control to do things such as enable paseli and adjust other
settings that you cannot normally access. Logs in an identical format to "bemanishark".
Useful for black-box RE of other networks. Note that this does not have the ability
to MITM SSL-encrypted traffic, so don't bother trying to use this on an official
network.

This also has the ability to route a packet to one of several known networks based on
the PCBID, so this can also be used as a proxy for switching networks on the fly.
With a config file, this can be used as a HTTP VIP of sorts, allowing you to point all of
your games at a single server that runs this proxy and forward games on a per-PCBID
basis to various networks behind the scenes. This can come in especially handy if you
are serving traffic from the same network your games are on. The network will auto-detect
the public-facing IP of games when they connect and use that info for matching support.
This breaks for local connections, so you might want to set up an offsite proxy instance
so that the correct public-facing IP is detected. For an example config file to use "proxy"
as a VIP, see `config/proxy.yaml`. For a more reliable proxy, use the wsgi version
of this utility located at `bemani/wsgi/proxy.wsgi` along with uWSGI and nginx.

Run it like `./proxy --help` to see how to use this utility.

## psmap

A utility to take an offset from a DLL/EXE file pointing at a psmap structure and
produce python code that would generate a suitable response that said DLL/EXE will
properly parse. Essentially, if you are reversing a new game and they use the `psmap`
function to decode all or part of a packet, you can grab either the physical offset
into the DLL or the virtual address of the data and use this utility to generate
the code necessary to service that request. Note that some psmap structures are
dynamically generated at runtime. "psmap" supports this by emulating x86 and x64 code
to reconstruct the final structure. This feature can be optionally enabled if needed.
Run it like `./psmap --help` to see how to use this utility.

## read

A utility to read music DB information out of game files and populate a database.
This should be given the same config file as "api", "services" or "frontend" and
assumes that "dbutils" has already been used to instantiate a valid MySQL DB. It
also assumes you have the correct game files to read out of. Run it like
`./read --help` to see how to use it. This utility's uses are extensively documented
below in the "Installation" section.

## replay

A utility to take a packet as logged by "proxy", "services", "trafficgen" or
"bemanishark", and replay that packet against a particular server. Useful for
quickly grabbing packets that caused a crash and debugging the crash (and verifying
the fix). It is also compatible with the packet logs found on exception and unsupported
packet messages in the Admin Event Logs page on the frontend. It also lets you
replay that packet against your production instance once you fix the issue in case
that packet was a score or profile update that you care about. Run it like
`./replay --help` to see all information and usage.

## responsegen

A utility to take a packet as logged by "proxy", "services", "trafficgen" or
"bemanishark", and generate python code that would have generated that exact packet.
Useful for quickly grabbing packets sniffed from another network and prototyping new
game support. Think of this as a combination of "replay" and "psmap". This is also
extremely useful when building new integration test clients. Run it like
`./responsegen --help` to see all information and usage.

## sampleclient

A very barebones sample client for the BEMAPI implementation contained in this repo.
Run it like `./sampleclient --help` to see help output and determine how to use this.
Essentially, this is provided as a barebones client that does nothing other than
print fetched info to the screen. You can use this as a starting point for an
application that uses BEMAPI to fetch info from an "api" instance or to test your
production installation to make sure it is ready for federation.

## scheduler

A command-line utility for kicking off scheduled work that must be performed against the
DB. This includes picking new dailies/weeklies, new courses, and others depending on the
game and any requirements that the server perform some actual calculation based on
time. Essentially, any game backend that includes a `run_scheduled_work` override will
be acted on by this utility. Note that this takes care of scheduling cadence and
should be seen as a utility-specific cron handler. You can safely run this repeatedly
and as frequently as desired. Run like `./scheduler --help` to see how to ues this.
This should be given the same config file as "api", "frontend" and "services".

## services

Development version of an eAmusement protocol server using flask and the protocol
libraries also used in "bemanishark" and "trafficgen". Currently it lets most modern
BEMANI games boot and supports full scores, profile and events for Beatmania IIDX 20-26,
Pop'n Music 19-26, Jubeat Saucer, Saucer Fulfill, Prop, Qubell, Clan and Festo, Sound
Voltex 1, 2, 3 Season 1/2 and 4, Dance Dance Revolution X2, X3, 2013, 2014 and Ace,
MÚSECA 1, MÚSECA 1+1/2, MÚSECA Plus, Reflec Beat, Limelight, Colette, groovin'!! Upper,
Volzza 1 and Volzza 2, Metal Gear Arcade, and finally The\*BishiBashi. Note that it also
has matching support for all Reflec Beat versions as well as MGA. By default, this serves
traffic based solely on the database it is configured against. If you federate with
other networks using the "Data API" admin page, it will upgrade to serving traffic
based on the profiles, scores and statistics of all connected networks as well as the
local database. Run like `./services --help` to see how to use this.

Do not use this utility to serve production traffic. Instead, see
`bemani/wsgi/api.wsgi` for a ready-to-go WSGI file that can be used with a Python
virtualenv containing this project and its dependencies, uWSGI and nginx.

## shell

A convenience wrapper to invoke a Python 3 shell that has paths set up to import the
modules in this repository. If you want to tinker or write a quick one-off, this is
probably the easiest way to do so. Run this like `./shell` to drop into a Python REPL
which has the paths set up for correct imports.

## struct

A convenience utility for helping reverse-engineer structures out of game DLLs/EXEs.
You can give this a physical DLL offset or a virtual memory address for the start and
end of the data as well as a python struct format (documentation at
https://docs.python.org/3.6/library/struct.html) and this will print the decoded
data to the screen one entry per line. It includes several enhancements for decoding
pointers to sub-structures and pointers to C strings. Note that much like "psmap", this
has the ability to print out structures that are dynamically constructed at runtime by
emulating x86 and x64 instructions. Run it like `./struct --help` to see how to use this.

## tdxtfiles

Utilities for working with raw TDXT texture files. These are found packed inside TXP2
and TEXP containers but sometimes can be found standalone. This utility has the capability
to extract a PNG of the texture for all known texture formats that I've come across, and
can repack a TDXT file given a PNG of the same size under certain circumstances. Not all
texture formats are supported for repacking. Run it like `./tdxtutils --help` to see help
output and determine how to use it.

## trafficgen

A utility for simulating traffic to an eAmusement service. Given a particular game,
this will run through and attempt to verify simple operation of that service. No
guarantees are made on the accuracy of the emulation though I've strived to be
correct. In some cases, I will verify the response, and in other cases I will
simply verify that certain things exist so as not to crash a real client. This
currently generates traffic emulating Beatmania IIDX 20-26, Pop'n Music 19-26, Jubeat
Saucer, Fulfill, Prop, Qubell, Clan and Festo, Sound Voltex 1, 2, 3 Season 1/2 and 4,
Dance Dance Revolution X2, X3, 2013, 2014 and Ace, The\*BishiBashi, MÚSECA 1 and MÚSECA
1+1/2, Reflec Beat, Reflec Beat Limelight, Reflec Beat Colette, groovin'!! Upper,
Volzza 1 and Volzza 2 ad Metal Gear Arcade and can verify card events and score events
as well as PASELI transactions. Run it like `./trafficgen --help` to see how to use this.
Note tha this takes a config file which sets up how the clients behave. See
`config/trafficgen.yaml` for a sample file that can be used.

## verifylibs

Unit test frontend utility. This will invoke nosetests on the embarrasingly small
collection of unit tests for this repository. If you are making modifications, it can
be useful to write a test first (placed in the `bemani/tests/` directory) and code
from there. It is also useful when optimizing or profiling, and also to verify that
you haven't regressed anything. Supports all options that nosetests does including
filtering, verbose printing and such. Run it like `./verifylibs --help` to see how
to do these things. When submitting pull requests make sure to run this across all
tests by running `./verifylibs` so you know that all tests pass.

## verifylint

Lint invocation utility. This simply invokes flake8 with various options so that you
can see you haven't introduced any lint errors. When submitting pull requests make sure
to run this so you know you aren't introducing any lint errors into the codebase. Run
it like `./verifylint` to print out any lint warnings your modifications have caused.

## verifytraffic

A utility which attempts to call "trafficgen" for each supported game on the network.
Think of this as a full integration test suite, as it will sweep through each supported
game and verify that network services are actually working. This assumes that you are
running "services". Do not point this at a production instance since it **will**
submit bogus cards, scores, names and the like and mess up your network. This takes
a config file which sets up how the client should behave. See `config/trafficgen.yaml`
for a sample file that can be used. When submitting pull requests make sure to run
this against a development version of your server so you know you haven't broken any
existing game implementations.

## verifytyping

Type-checking invocation utility. Since this repository is fully typed, this verifies
that you haven't introduced any type errors and often catches bugs far faster than
attemping to play a round only to see that you misused a class or misspelled a variable.
When submitting pull requests make sure to run this like `./verifytyping` so you know
you aren't introducing any type errors into the codebase.

# Installation

## Dependency Setup

The code contained here assumes Python 3.6 as the base although it should work with
any newer version of python as well. If you don't have or don't want to install Python
3.6 as your system python, it is recommended to use virtualenv to create a virtual
environment. The rest of the installation will assume you have Python 3.6 working
properly (and are in an activated virtual environment if this is the route you've
chosen to go). If you have a newer version of python available this code should be
compatible with that as well. This code is designed to run on Linux. However, it has
been tested successfully on Windows and OSX as it doesn't use any system-specific
libraries and contains pure Python implementations of all necessary pieces. YMMV in
this regard, however, since the whole suite is built and tested using a Debian-based
derivative and several critical pieces of code have much faster Cython implementations.

To install the required libraries, run the following command out of the root of the
repository. This should allow all of the programs to at least start, but it still
requires a MySQL database for many of them to be useful. This step has a dependency
on an isntalled MySQL server and client as well as MySQL client development libraries.
It also assumes that you've installed the 'wheel' python package already. In order to
compile the mysql client libraries, you will need to have libssl and libcrypto on your
system as well. To satisfy these requirements on a Debian-based install, run the
following command:

```
sudo apt install libssl-dev zlib1g-dev mysql-server mysql-client libmysqlclient-dev
```

Once you have all of the above present, run the following command:

```
pip install -r requirements.txt
```

Installing MySQL is outside the scope of this readme, so it is assumed that you have
a MySQL database with permission to create a new DB and tables within it. Note that this
software requires MySQL version 5.7 or greater. This is due to the extensive use of
the "json" column type added in 5.7. Create a database (the default database with
this code is 'bemani') accessed by some user and password (the default user/pass for
this code is 'bemani'/'bemani'). To create all of the required tables for the
installation, run the following, substituting the config file for one that you've
customized if you've done so. The config file that you use here should also be used
with "api", "services", and "frontend" as well as various other utilities documented
above.

```
./dbutils --config config/server.yaml create
```

In order to run the frontend, Python will need to find a javascript runtime. This
is so it can precompile react components at render time so there doesn't need to be
a compile step when developing the front-end. I found it absolutely bonkers that the
backend could be on-the-fly reloaded but I had to go through an entire build process
to produce interpreted JS code, so I went the route of self-contained services
instead. Installing a JS runtime is also outside the scope of this document, but a
quick way to get started is to install node.js.

The default configuration points the frontend/backend cache at `/tmp`. If you are going
to run with a filesystem cache in production then it is recommended to change to a
different directory, as using `/tmp` can cause some items not to be cached. This is
due to the way `/tmp` on Linux restricts file access to the creator only, so if you share
your cache with multiple utilities running under different users, it will fail to reuse
the cache and drastically slow down the frontend. Alternatively, you can set up a
memcached server and point your production instance at that instead of using a filesystem
cache.

## Database Initialization

At this point, games will boot when pointed at the network, but you won't be able
to save scores. This is due to the missing song/chart -> score mapping. You will find
default configuration files for the traffic generator and the services backend in
the config/ directory. If you've customized your database setup, you will want to
update the hostname/username/password/database in the configs. You will also want to update
the server address and frontend URL to customize your instance.

To create the song/chart -> score mapping, you will want to run through the following
section to import data from each game series. Be sure to substitute your own services
config in place of the default if you've customized it. Note that if there have been updates
to the files since you initially imported, you can run with the `--update` flag which
forces the metadata to be overwritten in the DB instead of skipped. This won't normally
happen, but if you make improvements to music DB parsing, you will want to do this to update
your database.

Note that you'll see a lot of re-used song entries. That will happen when the import script
finds an existing set of charts for the same song in a different game version and links
the two game versions together. This is how scores can be shared across different versions
of the same game.

If you happen to already be an authorized client of a BEMAPI-compatible server, you can
fast-track initializing your server by pointing it at the remote server and using its existing
database to seed your own. If this is the case, run the following command to perform
a complete initialization. Note that the "bootstrap" script has entries for non-omnimix
versions only. You can edit it to add omnimix versions as well if you wish to provide
omnimix support and are pointing at another BEMAPI-compatible instance which also has
support. If you wish to update your initial setup with newer data, perhaps because a
new supported game is available, you can run the following script and append the
`--update` flag to it. Otherwise, run the following command like so:

```
./bootstrap --config config/server.yaml --server http://some-server.here/ --token some-token-here
```

If you are not federating with an existing BEMAPI-compatible server, you can initialize
the server from the game files of the games you wish to run. See the following sections
for how exactly to do that.

### Pop'n Music

For Pop'n Music, get the game DLL from the version of the game you want to import and
run a command like so. This network supports versions 19-26 so you will want to run this
command once for every version, giving the correct DLL file. Note that there are several
versions of each game floating around and the "read" script attempts to support as many
as it can but you might encounter a version of the game which hasn't been mapped yet.

An example is as follows:

```
./read --config config/server.yaml --series pnm --version 22 --bin popn22.dll
```

If you are looking to support omnimix v2, you can add songs out of an XML like this:

```
./read --config config/server.yaml --series pnm --version omni-24 --bin popn24.dll --xml your_songs_db.xml
```

If you have more than one XML you want to add, you can run this command with a folder with all your XML files:

```
./read --config config/server.yaml --series pnm --version omni-24 --bin popn24.dll --folder my/xmls/path
```

### Jubeat

For Jubeat, get the music XML out of the data directory of the mix you are importing,
and then use "read" with `--series jubeat` and `--version` corresponding to the following
table:

* Saucer:         saucer
* Saucer Fulfill: saucer-fulfill
* Prop:           prop
* Qubell:         qubell
* Clan:           clan
* Festo:          festo

An example is as follows:

```
./read --config config/server.yaml --series jubeat --version saucer --xml music_info.xml
```

You will also want to populate the Jubeat name database with the following command
after importing all mixes:

```
./read --config config/server.yaml --series jubeat --version all --tsv data/jubeat.tsv
```

For Jubeat Prop and later versions, you will also need to import the emblem DB, or emblems
will not work properly. An example is as follows:

```
./read --config config/server.yaml --series jubeat --version prop \
      --xml data/emblem-info/emblem-info.xml
```

If you wish to display emblem graphics on the frontend, you will also need to convert the
emblem assets. Failing to do so will disable the emblem graphics rendering feature for the
frontend. Note that this only applies to versions where you have also imported the emblem
DB. An example is as follows:

```
./assetparse --config config/server.yaml --series jubeat --version prop \
      --xml data/emblem-info/emblem-info.xml --assets data/emblem-textures/
```

### IIDX

For IIDX, you will need the data directory of the mix you wish to support. The import
script automatically scrapes the music DB as well as the song charts to determine
difficulty, notecounts and BPM. For a normal mix, you will want to run the command like
so. This network supports versions 20-26 so you will want to run this command once for
every version, giving the correct bin file:

```
./read --config config/server.yaml --series iidx --version 22 --bin \
      gamedata/data/info/music_data.bin --assets gamedata/data/sound/
```

Note that for omnimix mixes, you will need to point at the omnimix version of
`music_data.bin`, normally named `music_omni.bin`. For the version, prepend "omni-" to the
number, like so:

```
./read --config config/server.yaml --series iidx --version omni-22 --bin \
      gamedata/data/info/music_omni.bin --assets gamedata/data/sound/
```

You will also want to update the IIDX name database with the following command
after importing all mixes (this fixes some inconsistencies in names):

```
./read --config config/server.yaml --series iidx --version all --tsv \
      data/iidx.tsv
```

For Qpro editing to work properly, you will also need to import the Qpro database from
the mix you wish to support. This does not need to be run separately for omnimix versions,
the base version Qpros will be used for both that version and the omnimix of that version.
This network supports editing Qpros for versions 20-26 so you will want to run this command
once for every version, giving the correct DLL file:

```
./read --config config/server.yaml --series iidx --version 22 --bin bm2dx.dll
```

### DDR

For DDR, you will need the game DLL and `musicdb.xml` from the game you wish to import,
and then run a command similar to the following. You will want to use the version
corresponding to version in the following table:

* X2:            12
* X3 vs. 2ndMix: 13
* 2013:          14
* 2014:          15
* Ace:           16

```
./read --config config/server.yaml --series ddr --version 15 --bin ddr.dll --xml data/musicdb.xml
```

For DDR Ace, there is no `musicdb.xml` or game DLL needed. Instead, you will need the
`startup.arc` file, like the following example:

```
./read --config config/server.yaml --series ddr --version 16 --bin data/arc/startup.arc
```

### SDVX

For SDVX, you will need the game DLL and `music_db.xml` from the game you wish to import,
and then run the following command, modifying the version parameter as required.
Note that for SDVX 1, you want the `music_db.xml` file in `data/others/music_db/` directory,
but for SDVX 2 and onward, you will want the file in `data/others/` instead.

```
./read --config config/server.yaml --series sdvx --version 1 \
      --xml data/others/music_db.xml
```

For SDVX 1, you will also need to import the item DB, or appeal cards will not work
properly. To do so, run the following command.

```
./read --config config/server.yaml --series sdvx --version 1 \
      --bin soundvoltex.dll
```

For SDVX 2 and 3, you will also need to import the appeal message DB, or appeal cards
will not work properly. To do so, run the following command, substituting the correct
version number.

```
./read --config config/server.yaml --series sdvx --version 2 \
      --csv data/others/appealmessage.csv
```

For SDVX 4, you will also need to import the appeal card DB, or appeal cards will not
work properly. To do so, run the following command.

```
./read --config config/server.yaml --series sdvx --version 4 \
      --xml data/others/appeal_card.xml
```

### MÚSECA

For MÚSECA, you will need the `music-info.xml` file from the game you wish to import.
Then, run the following command, modifying the version parameter as required.

```
./read --config config/server.yaml --series museca --version 1 \
      --xml data/museca/xml/music-info.xml
```

### Reflec Beat

For Reflec Beat, get the game DLL from the version of the game you want to import and
run a command like so. This network supports Reflec Beat up through Volzza 2, so you
will want to run this with versions 1-6 to completely initialize. Use the version
corresponding to version in the following table:

* Reflec Beat: 1
* Limelight: 2
* Colette: 3
* Groovin'!!: 4
* VOLZZA: 5
* VOLZZA 2: 6

```
./read --config config/server.yaml --series reflec --version 1 --bin reflecbeat.dll
```

## Running Locally

Once you've set all of this up, you can start the network in debug mode using a command
similar to:

```
./services --port 5730 --config config/server.yaml
```

You can start the frontend in debug mode using another similar command as such:

```
./frontend --port 8573 --config config/server.yaml
```

You can start the BEMAPI REST server in debug mode using a command similar to:

```
./api --port 18573 --config config/server.yaml
```

You can run scheduled work to generate dailies and other such things using a command like so:

```
./scheduler --config config/server.yaml
```

The network config for any particular game should look similar to the following, with
the correct hostname or IP filled in for the services URL. No path is necessary. Note
that if you wish to switch between an existing network and one you serve using the
"proxy" utility, you can set up the services URL to include subdirectories as required
by that network. This code does not examine nor care about anything after the initial
slash, so it can be whatever.

```
<network>
    <timeout __type="u32">30000</timeout>
    <sz_xrpc_buf __type="u32">102400</sz_xrpc_buf>
    <ssl __type="bool">0</ssl>
    <services __type="str">http://127.0.0.1:5730/</services>
</network>
```

If you wish to verify the network's operation with some test traffic, feel free to
point the traffic generator at your development network. You should run it similar to
the command below, substituting the correct port to connect to your network and choosing
one of the supported games. If you don't know a supported game, you can use the `--list`
option to print them. If "Success!" is printed after all checks, you're good to go!

```
./trafficgen --config config/trafficgen.yaml --port 5730 --game pnm-22 && echo Success!
```

You will want to set up a cron job or similar scheduling agent to call "scheduler"
on a regular basis. It is recommended to call it every five minutes since there are cache
warming portions for the front-end that expire every 10 minutes. Game code will register
with internal handlers to perform daily/weekly actions which are kicked off by this script.
Note that if you don't want to have this done automatically in your development environment,
you can simply invoke it before testing with a game. An example invocation of the tool is
as follows:

```
./scheduler --config config/server.yaml
```

Once your network is up and running, if you pull new code down, the DB schema may have
changed. For that, use the same DB util script detailed above in the following manner.
This will walk through all migration scripts that you haven't applied and bring your DB
up to spec. It is recommended to create a deploy script that knows how to install dependencies
and install a new version of these utilities to your production virtualenv and then runs the
following script to ensure that your production DB is kept in sync with upstream changes:

```
./dbutils --config config/server.yaml upgrade
```

Since the network provided is player-first, in order to promote an account to administrator
you will have to create an account on a game first. Once you have done that, you can sign
up for the front-end using those credentials (your card and PIN), and then use the dbutils
script to promote yourself to admin, similar to this command:

```
./dbutils --config config/server.yaml add-admin --username <your-name-here>
```

Once you have create an admin account, you can use tools on the frontend to establish
arcades and their owners. Any administrator can check system settings including event
logs, configure news entries, help users recover passwords and change cards and the like.
Arcade owners can choose how paseli is supported on the machines in their arcade, grant
users credits and configure game options such as which events are active.

## Troubleshooting

If you followed the above instructions, the network should "Just Work" for you. However
there are several gotchas and caveats that might not be obvious to a first-time user of
this software. If you run into trouble these troubleshooting steps may help.

### Logs show that games only request the initial services packet. Additional packets are not sent and games do not go online.

The initial services packet is akin to a DNS request. The response tells games where to
go for each service. The values sent by the server are controlled in `config/server.yaml`.
Make sure the domain or IP in the `server.address` config entry is correct for the
computer you're running services on. Make sure that the IP the DNS entry resolves to,
or the literal IP you've typed in this setting is routable from the game's perspective.
Make sure that the port setting in `server.port` is the same as you've specified in your
command line if you are launching the debug program, or the same as your webserver
config if you are setting up a production instance. Make sure that the specified port
is unblocked in any firewall running on the computer you're running services on.

### Games connect to the server, logs show successful exchanges, there are no exceptions and the game boots fine but freezes on the attract screen or refuses to mark itself as "online".

Even if 100% of the network packets are responded to correctly, if the game itself can't
ping the keepalive host it will refuse to enable online services. Verifiy the
`server.keepalive` setting in `config/server.yaml` to make sure that it points at a
computer that can be reached by the game. Make sure that that computer has enabled ICMP
replies such as ping. Routers often block ping requests. It is recommended that you leave
this as `127.0.0.1` as it will cause the game to ping itself and get a successful reply.
This removes the usefulness of the network test screen outside of the IP setup but it is
known to work.

### pip install fails to compile MySQL on an ARM-based Mac

It appears that if you are installing this software on an ARM-based OSX machine and you
have installed dependencies using brew, library paths are not correctly set up for MySQL
to find the zstd library. As a result, `pip install -r requirements.txt` will fail with
a cryptic error message including the line `ld: library not found for -lzstd`. The
workaround is to specify the zstd library path manually in the pip install line. Try
running the following (or a variation of the following if you've modified your pip
install line already): `LDFLAGS="-L$(brew --prefix zstd)/lib" pip install -r requirements.txt`.

### JSX files fail to compile, music databases fail to read from game files on Windows

Apparently on Windows, the default encoding is unset for Python in some installations.
This can lead to some incredibly confusing errors as JSX files will fail to compile when
you attempt to load the front-end, and importing music databases from various games will
crash with encoding errors. If you run into this problem, you can set a few environment
variables to fix the issue. Make sure that the following are set:

```
export PYTHONIOENCODING=utf-8
export PYTHONLEGACYWINDOWSSTDIO=utf-8
```

### None of my own games pointing at my self-hosted network can be matched with

This is due to the way routers handle internal connections to their public-facing IP.
Even if you tell your games to connect to the DNS entry or public-facing IP of your
network, the router will handle the request internally. Therefore, all of the games
on your own local network will have their public-facing IP detected wrong. You can
get around this by either hosting your network services off-site, or paying for cheap
colocation somewhere and running a "proxy" instance there. The proxy utility (and its
production wsgi counterpart) know how to forward the detected IP through any number of
proxy hops. Once you have set up an external proxy relay or moved your network services
off-site, your own games will get their public-facing IP detected correctly. Remember
that you should still forward the port assigned to each game on the admin interface.

## Production Setup

As alluded to several times in this README, the recommended way to run a production
instance of this code is to set up uWSGI fronted by nginx. You should SSL-encrypt
the frontend and the API services, and its recommended to use LetsEncrypt for a
free certificate that you can manage easily. There are other ways to run this software
and provide SSL credentials but I have no experience with or advice on them.

The easiest way to get up and running is to install MySQL 5.7, nginx and uWSGI along
with Python 3.6 or higher. Create a directory where the services will live and place
a virtualenv inside it (outside the scope of this document). Then, the wsgi files found
in `bemani/wsgi/` can be placed in the directory, uWSGI pointed at them and nginx set up.
The setup for the top-level package will include all of the frontend templates, so you
can set up a nginx directory to serve the static resources directly by pointing at the
static directory inside your virtualenv. If you use "assetparse" to extract assets or
"jsx" to compile static JS, you'll want to add entries in your nginx config to serve
those as well.

For example configurations, an example install script, and an example script to back
up your MySQL instance, see the `examples/` directory. Note that several files have
sections where you are expected to substitute your own values so please read over them
carefully.

# Contributing

Contributions are welcome! Before submitting a pull request, ensure that your code
is type-hint clean by running `./verifytyping` and ensure that it hasn't broken basic
libraries with `./verifylibs`. Make sure that it is also lint-clean with `./verifylint`.
You should also make sure its formatted correctly by running `./formatfiles`.
If you are changing code related to a particular game, it is required to include a
verification in the form of a game traffic emulator, so that basic functionality can
be verified. To ensure you haven't broken another game with your changes, its recommended
to run the traffic generator against your code with various games. For convenience, you
can run `./verifytraffic --config config/trafficgen.yaml` to run all supported games
against your change. Remember that some games require you to run the scheduler to
generate dailies/weeklies, and if you neglect to run this some of the integration
tests will fail as they require full packet support! If possible, please also write
a unit test for your changes. However, if the unit test is just a tautology and an
integration/traffic test will suit better, then do that instead.

For documentation on how the protocol layer works, see "PROTOCOL". For documentation
on how the eAmusement server is intended to work, see "BACKEND". Inside `bemani/data/`
the various DB model files have comments detailing the intended usage of each of the
tables. For documentation on how the BEMAPI REST API should respond, please see the
BEMAPI specification in `bemani/api/`.

When updating DB schema in the various `bemani/data/` python files, you will most-likely
want to generate a migration for others to use. For that, we've integrated with alembic
in order to provide robust migrations. The same DB utility script detailed above will
create a migration script for you, given a message specifying the operation taking place.
You should run this **after** making the code change to the schema in the relevant
file under `bemani/data/mysql`. Alembic will automatically diff your development MySQL
DB against the schema change you've made and generate an appropriate migration. Sometimes
you will want to augment that migration with addtional data transformations. Various
existing migrations do just that, so have a look at them under
`bemani/data/migrations/versions/`. An example is as follows:

```
./dbutils --config config/server.yaml generate --message "Adding timestamp column to user."
```

Once the script finishes, check out the created migration script to be sure its correct
and then check it in.

# Development Tips

Several core components of this repo have a parallel C++ implementation for massive
speed boosts. Several components are also cythonized to squeeze a bit more speed out of
them as well. This project aims to provide a pure-python implementation of everything so
it is not necessary to run with cythonized or compiled code either in development or
production. However, if you want to benefit from the massive speed bumps provided by
the equivalent implementations you can compile the code in-place for your development
setup. The following will compile all needed libraries assuming you have a working
C++ compiler and cython is set up to run on your computer:

```
python3 setup.py build_ext --inplace
```

If you are modifying files that have an equivalent C++ implementation and it changes
their semantics, make sure to test both paths! If you are modifying code that is
cythonized and you've compiled, make sure to re-run the above command or delete the
compiled `.so` files, otherwise your changes will not show up when you test.

# License and Usage

All of the code in this repository is released under the public domain. No attribution or
releasing of source code is required. No warranty of the code or functionality is implied.
However, open source would not flourish without contributions from users the world across.
Pull requests are therefore appreciated! Please note, however, that the code contained in this
repo is meant to facilitate preservation and personal enjoyment of otherwise lost versions
of various arcade games. Do not attempt to check in anything legally owned by a business
or personal entity including source code, images, siterips, game files or anything
similar. Do not attempt to check in support for games currently being offered for sale
by the original manufacturer or games which have not reached their support end-of-life.

Similarly, while I cannot control what you decide to do with this software, it would be
very, very stupid to attempt to run this in a public arcade or convention, or to attempt
to use this with games that you or another person or business are charging money for. If
you decide to do this anyway, do not advertise association with any of this software in
any form whatsoever. Attempting to use this software for commercial gain or to compete
publicly with official game support goes directly against the stated goals of this software.
