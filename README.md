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

A utility for unpacking and repacking `.2dx` files. This isn't the best utility and
I think there are more complete and more accurate programs out there. However,
they all lack source as far as I could tell, so I developed this. Run it like
`./2dxutils --help` to see help output and determine how to use this.

## api

Development version of this repository's BEMAPI implementation. Run it like
`./api --help` to see help output and determine how to use this. Much like
"services" and "frontend", this should be pointed at the development version of
your services config file, which holds information about the MySQL database that
this should connect to as well as what game series are supported. See
`config/server.yaml` for an example file that you can modify.

Do not use this utility to serve production traffic. Instead, see
`bemani/wsgi/api.wsgi` for a ready-to-go WSGI file that can be used with uWSGI
and nginx.

## arcutils

A utility for unpacking `.arc` files. This does not currently repack files. However,
the format is so trivial that adding such a feature would be fairly easy. Run it
like `./arcutils --help` to see help output and determine how to use this.

## bemanishark

A wire sniffer that can decode eAmuse packets and print them. Run it on a computer
that can sniff traffic between an eAmusement server and a supported game and it will
spit out the requests and responses XML-formatted identically to the legacy easerver
XML output. This works on both binary and XML traffic. Note that it does not have the
capability to sniff SSL-encrypted traffic, so don't even bother trying to run this
at an arcade with official support.

Run it like `sudo ./bemanishark` to invoke. Will run indefinitely until killed
(Ctrl-C will suffice). Run like `./bemanishark --help for options. Without options,
it assumes you want to sniff port 80 for all addresses. Note that it doesn't support
the Base64 binary blob formats found in SN1 and 2. Note also that over time it will
start to lose packets. This is a bug that I never figured out, and it appears to be
the OS failing to send over some packets resulting in a failure to reassemble the
TCP stream.

This utility might be better if rewritten to be a plugin for Wireshark instead of
a standalone sniffing utility, but I don't have the time.

## binutils

A utility for unpacking raw binxml files (files that use the same encoding scheme
as the binary network protocol) to their XML representation. This is useful for
examining raw binary blobs or digging into unknown file formats that contain binxml.
Run it like `./binutils --help` to see help and learn how to use this.

## bootstrap

A utility for quickly bootstrapping a local setup's music database from an already
running BEMAPI-compatible server. This is more documented in the below "Database
Initialization" section.

## cardconvert

A command-line utility for converting between card numbers written on the back of a
card and the card ID stored in the RFID of the card. Run it like `./cardconvert --help`
to see how to use this. This will sanitize input, so you can feed it card numbers
with or without spaces, and you can mix up 1 and I as well as 0 and O, and it will
properly handle decoding. This supports both new and old style cards.

## dbutils

A command-line utility for working with the DB used by "api", "services" and "frontend".
This utility includes options for creating tables in a newly-created DB, granting and
revoking admin rights to the frontend, generating migration scripts for live DBs, and
upgrading live DBs based on previously created migration scripts. Its driven by alembic
under the hood. You will use `create` on initial setup to generate a working MySQL
database. If you change the schema in code, you can use this again with the `generate`
option to generate a migration sript. Whenever you run an upgrade to your production
instance, you should run this against your production DB with the `upgrade` option to
bring your production DB up to sync with the code you are deploying. Run it like
`./dbutils --help` to see all options. The config file that this works on is the same
that is given to "api", "services" and "frontend".

## frontend

Development version of a frontend server allowing for account and server administration
as well as score viewing and profile editing. Run it like `./frontend --help` to see
help output and determine how to use this. Much like "services" and "api", this should
be pointed at the development version of your services config file, which holds
information about the MySQL database that this should connect to as well as what game
series are supported. See `config/server.yaml` for an example file that you can modify.

Do not use this utility to serve production traffic. Instead, see
`bemani/wsgi/frontend.wsgi` for a ready-to-go WSGI file that can be used with uWSGI
and nginx.

## ifsutils

A mediocre utility that can extract `.ifs` files. This has a lot of baked in
assumptions and is not nearly as good as other open-source utilities for extracting
files. It also cannot repack files. This is included for posterity, and because some
bootstrapping code requires it in order to fully start a production server.
Run it like `./ifsutils --help` to see help output and learn how to use it.

## iidxutils

A utility for patching IIDX music database files. Note that this currently can only
apply a "hide leggendarias from normal folders" patch, although its probable that it
can be extended for other uses.

## proxy

A utility to MITM an eAmuse session. Point a game at the port this listens on, and
point it at another network to see the packets flowing between the two. Takes care
of rewriting the facility message to MITM all messages. Has the ability to rewrite
a request/response on the fly which is not currently used except for facility rewriting.
Its possible that this could be used to on-the-fly patch packets coming back from a
network which you don't control to do things such as enable paseli and adjust other
settings that you cannot normally access. Logs in an identical format to bemanishark.
Useful for black-box RE of other networks. Note that this does not have the ability
to MITM SSL-encrypted traffic, so don't bother trying to use this on an official network.

This also has the ability to route a packet to one of several known networks based on
the PCBID, so this can also be used as a proxy for switching networks on the fly.
With a config file, this can be used as a VIP of sorts, allowing you to point all of
your games at a single server that runs this proxy, and forward games on a per-PCBID
basis to various networks behind the scenes. For an example config file to use "proxy"
as a VIP, see `config/proxy.yaml`. For a more reliable proxy, use the wsgi version
of this utility located at `bemani/wsgi/proxy.wsgi` along with uWSGI and nginx.

Run it like `./proxy --help` to see how to use this utility.

## psmap

A utility to take an offset from a DLL file and produce python code that would generate
a suitable response that said DLL will properly parse. Essentially, if you are
reversing a new game and they use the `psmap` utility to decode all or part of a
packet, you can grab either the physical offset into the DLL or the virtual address of
the data and use this utility to generate the code necessary to service that request.
Note that this doesn't currently work on 64bit games, but it should be trivial to
figure out the differences in the 64-bit psmap implementation. Run it like
`./psmap --help` to see how to use this utility.

## read

A utility to read music DB information out of game files and populate a database.
This should be given the same config file as "api", "services" or "frontend" and
assumes that "dbutils" has already been used to instantiate a valid MySQL DB. It
also assumes you have the correct game files to read out of. Run it like
`./read --help` to see how to use it. This utility's uses are extensively documented
below in the "Installation" section.

## replay

A utility to take a packet as logged by proxy, services, trafficgen or bemanishark,
and replay that packet against a particular server. Useful for quickly grabbing
packets that caused a crash and debugging the crash (and verifying the fix). It also
lets you replay that packet against your production instance once you fixed the issue
in case that packet was a score or profile update that you care about.

## responsegen

A utility to take a packet as logged by proxy, services, trafficgen or bemanishark,
and generate python code that would have generated that exact packet. Useful for
quickly grabbing packets sniffed from another network and prototyping new game support.
Think of this as a combination of "replay" and "psmap". This is also extremely useful
when building new integration test clients. Run it like `./responsegen --help` to
see all information and usage.

## scheduler

A command-line utility for kicking off scheduled work that must be performed against a
DB. This includes picking new dailies/weeklies, new courses, etc... depending on the
game and any requirements that the server perform some actual calculation based on
time. Essentially, any game backend that includes a `run_scheduled_work` override will
be acted on by this utility. Note that this takes care of scheduling cadence and
should be seen as a utility-specific cron handler. You can safely run this repeatedly
and as frequently as desired. Run like `./scheduler --help` to see how to ues this.
This should be given the same config file as "api", "frontend" and "services".

## services

Development version of an eAmusement protocol server using flask and the protocol
libraries also used in "bemanishark" and "trafficgen". Currently it lets most modern
BEMANI games boot and supports full profile and events for Beatmania IIDX 20-24,
Pop'n Music 19-24, Jubeat Saucer, Saucer Fulfill, Prop, Qubell and Clan, Sound Voltex
1, 2, 3 Season 1/2 and 4, Dance Dance Revolution X2, X3, 2013, 2014 and Ace, MÚSECA 1,
MÚSECA 1+1/2, Reflec Beat, Limelight, Colette, groovin'!! Upper, Volzza 1 and Volzza 2,
and finally The\*BishiBashi.

Do not use this utility to serve production traffic. Instead, see
`bemani/wsgi/services.wsgi` for a ready-to-go WSGI file that can be used with uWSGI
and nginx.

## shell

A convenience wrapper to invoke a Python 3 shell that has paths set up to import the
modules in this repository. If you want to tinker or write a quick one-off, this is
probably the easiest way to do so.

## struct

A convenience utility for helping reverse-engineer structures out of game DLLs. You
can give this a physical DLL offset or a virtual memory address for the start and
end of the data as well as a python struct format (documentation at
https://docs.python.org/3.6/library/struct.html) and this will print the decoded
data to the screen as a series of tuples. Run it like `./struct --help` to see how
to use this.

## trafficgen

A utility for simulating traffic to an eAmusement service. Given a particular game,
this will run through and attempt to verify simple operation of that service. No
guarantees are made on the accuracy of the emulation though I've strived to be
correct. In some cases, I will verify the response, and in other cases I will
simply verify that certain things exist so as not to crash a real client. This
currently generates traffic emulating Beatmania IIDX 20-24, Pop'n Music 19-24, Jubeat
Saucer, Fulfill, Prop, Qubell and Clan, Sound Voltex 1, 2, 3 Season 1/2 and 4, Dance
Dance Revolution X2, X3, 2013, 2014 and Ace, The\*BishiBashi, MÚSECA 1 and MÚSECA 1+1/2,
Reflec Beat, Reflec Beat Limelight, Reflec Beat Colette, groovin'!! Upper, Volzza 1 and
Volzza 2 and can verify card events and score events, as well as PASELI transactions.

## verifylibs

Unit test frontend utility. This will invoke nosetests on the embarrasingly small
collection of unit tests for this repository. If you are making modifications, it can
be useful to write a test first (placed in the `bemani/tests/` directory) and code
from there. It is also useful when optimizing or profiling, and also to verify that
you haven't regressed anything.

## verifylint

Lint invocation utility. This simply invokes flake8 with various options so that you
can see you haven't introduced any lint errors.

## verifytraffic

A utility which attempts to call "trafficgen" for each supported game on the network.
Think of this as a full integration test suite, as it will sweep through each supported
game and verify that network services are actually working. This assumes that you are
running "services". Do not point this at a production instance since it **will**
submit bogus cards, scores, names and the like and mess up your network. This takes
a config file which sets up how the client should behave. See `config/trafficgen.yaml`
for a sample file that can be used.

## verifytyping

Typing invocation utility. Since this repository is fully typed, this verifies that you
haven't introduced any type errors and often catches bugs far faster than attemping to
play a round only to see that you misused a class or misspelled a variable.

# Installation

## Dependency Setup

The code contained here assumes Python 3.6 as the base. If you don't have or don't
want to install Python 3.6 as your system python, it is recommended to use
virtualenv to create a virtual environment. The rest of the installation will assume
you have Python 3.6 working properly (and are in an activated virtual environment if
this is the route you've chosen to go). This code is designed to run on Linux.
However, it has been tested successfully on Windows and OSX as it doesn't use any
system libraries and sticks to pure python. YMMV in this regard, however, since the
whole suite is built and tested using a Debian-based derivative.

To install the required libraries, run the following command out of the root of the
repository. This should allow all of the programs to at least start, but it still
requires a MySQL database for many of them to be useful. This step has a dependency
on an isntalled MySQL server and client as well as MySQL client development libraries.
It also assumes that you've installed the 'wheel' package already. In order to
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
a MySQL database with access to create a new DB and tables within it. Note that this
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
a compile step when developing. I found it absolutely bonkers that the backend could
be on-the-fly reloaded but I had to go through an entire build process to produce
interpreted JS code, so I went the route of self-contained services instead. Installing
a JS runtime is also outside the scope of this document, but a quick way to get started
is to install node.js.

The default configuration points the frontend/backend cache at `/tmp`. It is recommended
to change to a different directory, as using `/tmp` can cause some items not to be cached.
This is due to the way `/tmp` on Linux restricts file access to the creator only, so
if you share your cache with multiple utilities running under different users, it will
fail to reuse the cache and drastically slow down the frontend.

## Database Initialization

At this point, games will boot when pointed at the network, but you won't be able
to save scores. This is due to the missing song/chart -> score mapping. You will find
default configuration files for the traffic generator and the services backend in
the config/ directory. If you've customized your database setup, you will want to
update the hostname/username/password/database here. You will also want to update
the server address and frontend URL to customize your instance.

To create the song/chart -> score mapping, you will want to run through the following
section to import data from each game series. Be sure to substitute your own services
config in place of the default if you've customized it. Note that if there have been updates
to the files since you initially imported, you can run with the `--update` flag which
forces the metadata to be overwritten in the DB instead of skipped. This won't normally
happen, but if you make improvements to music DB parsing, you will want this to update
your network.

Note that you'll see a lot of re-used entries. That will happen when the import script
finds an existing set of charts for the same song in a different game version and links
the two game versions together. This is how scores can be shared across different versions
of the same game.

If you happen to already be an authorized client of a BEMAPI-compatible server, you can
fast-track initializing your server by pointing it at the remote and using its existing
database to seed your own. If this is the case, run the following command to perform
a complete initialization. If you wish to update your initial setup with newer data,
perhaps because a new supported game is available, you can run the following script and
append the `--update` flag to it. Otherwise, run the following command like so:

```
./bootstrap --config config/server.yaml --server http://some-server.here/ --token some-token-here
```

If you do not have a BEMAPI-compatible server, you can initialize the server from the
game files of the games you wish to run. See the following sections for how exactly to
do that.

### Pop'n Music

For Pop'n Music, get the game DLL from the version of the game you want to import and
run a command like so. This network supports versions 19-24 so you will want to run this
command once for every version, giving the correct DLL file:

```
./read --config config/server.yaml --series pnm --version 22 --bin popn22.dll
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

### IIDX

For IIDX, you will need the data directory of the mix you wish to support. The import
script automatically scrapes the music DB as well as the song charts to determine
difficulty, notecounts and BPM. For a normal mix, you will want to run the command like
so. This network supports versions 20-24 so you will want to run this command once for
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
will want to run this with versions 1-6 to completely initialize:

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
An example invocation of the tool is as follows:

```
./scheduler --config config/server.yaml
```

Once your network is up and running, if you pull new code down, the DB schema may have
changed. For that, use the same DB util script detailed above in the following manner.
This will walk through all migration scripts that you haven't applied and bring your DB
up to spec. It is recommended to create a deploy script that knows how to restart uWSGI,
install a new version of these utilities to your production virtualenv and then runs this
script to ensure that your production DB is kept in sync:

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

## Production Setup

As alluded to several times in this README, the recommended way to run a production
instance of this code is to set up uWSGI fronted by nginx. You should SSL-encrypt
the frontend and the API services, and its recommended to use LetsEncrypt for a
free certificate that you can manage easily. There are other ways to run this software
but I have no experience with or advice on them.

The easiest way to get up and running is to install MySQL 5.7, nginx and uWSGI along
with Python 3.6 or higher. Create a directory where the services will live and place
a virtualenv inside it (outside the scope of this document). Then, the wsgi files found
in `bemani/wsgi/` can be placed in here, uWSGI pointed at them and nginx set up. The
setup for the top-level package will include all of the frontend templates, so you can
set up a nginx directory to serve the static resources directly.

For example configurations, an example install script, and an example script to back
up your MySQL instance, see the `examples/` directory.

# Contributing

Contributions are welcome! Before submitting a pull request, ensure that your code
is type-hint clean by running `./verifytyping` and ensure that it hasn't broken basic
libraries with `./verifylibs`. Make sure that it is also lint-clean with `./verifylint`.
If you are changing code related to a particular game, it is nice to include a
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
BEMAPI specification repository at https://github.com/DragonMinded/bemapi.

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
