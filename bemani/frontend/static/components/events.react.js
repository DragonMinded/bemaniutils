/*** @jsx React.DOM */

var UnknownEvent = createReactClass({
    render: function() {
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="unknown">Unknown event {event.type}</td>
                <td className="details">
                    <div>Raw JSON:</div>
                    <LongMessage>{JSON.stringify(event.data, null, 4)}</LongMessage>
                </td>
            </tr>
        );
    },
});

var ExceptionEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        var location = 'Unknown Service';
        var details = 'No details for this type of exception!';
        if (event.data.service == 'frontend') {
            location = 'Web UI';
            details = (
                <>
                    <div>
                        <div className="inline">URI:</div>
                        <pre className="inline">{event.data.request}</pre>
                    </div>
                    <div>Exception:</div>
                    <LongMessage>{event.data.traceback}</LongMessage>
                </>
            );
        } else if(event.data.service == 'xrpc') {
            location = 'Game Services';
            details = (
                <>
                    <div>Request:</div>
                    <LongMessage>{event.data.request}</LongMessage>
                    <div>Exception:</div>
                    <LongMessage>{event.data.traceback}</LongMessage>
                </>
            );
        } else if(event.data.service == 'scheduler') {
            location = 'Work Scheduler';
            details = (
                <>
                    <div>Exception:</div>
                    <LongMessage>{event.data.traceback}</LongMessage>
                </>
            );
        } else if (event.data.service == 'api') {
            location = 'Data Exchange API';
            details = (
                <>
                    <div>
                        <div className="inline">URI:</div>
                        <pre className="inline">{event.data.request}</pre>
                    </div>
                    <div>Exception:</div>
                    <LongMessage>{event.data.traceback}</LongMessage>
                </>
            );
        }

        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="exception">
                    <div className="circle" />
                    Exception Occurred In {location}
                </td>
                <td className="details">{details}</td>
            </tr>
        );
    },
});

var UnhandledPacketEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="unhandled">
                    <div className="circle" />
                    Unhandled Packet Received In Game Services
                </td>
                <td className="details">
                    <div>Request:</div>
                    <LongMessage>{event.data.request}</LongMessage>
                </td>
            </tr>
        );
    },
});

var UnauthorizedClientEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="unauthorized">
                    <div className="circle" />
                    Unauthorized Client Connected To Game Services
                </td>
                <td className="details">
                    <div>
                        <div className="inline">Model:</div>
                        <pre className="inline">{event.data.model}</pre>
                    </div>
                    <div>
                        <div className="inline">PCBID:</div>
                        <pre className="inline">{event.data.pcbid}</pre>
                    </div>
                    <div>
                        <div className="inline">IP Addres:</div>
                        <pre className="inline">{event.data.ip}</pre>
                    </div>
                </td>
            </tr>
        );
    },
});

var PCBEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="pcbevent">
                    <div className="circle" />
                    PCB Event
                </td>
                <td className="details">
                    <div>
                        <div className="inline">Model:</div>
                        <pre className="inline">{event.data.model}</pre>
                    </div>
                    <div>
                        <div className="inline">PCBID:</div>
                        <pre className="inline">{event.data.pcbid}</pre>
                    </div>
                    <div>
                        <div className="inline">IP Addres:</div>
                        <pre className="inline">{event.data.ip}</pre>
                    </div>
                    <div>
                        <div className="inline">Name:</div>
                        <pre className="inline">{event.data.name}</pre>
                    </div>
                    <div>
                        <div className="inline">Value:</div>
                        <pre className="inline">{event.data.value}</pre>
                    </div>
                </td>
            </tr>
        );
    },
});

var PASELITransactionEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        var username = null;
        var user = null;
        if (this.props.users) {
            if (this.props.users[event.userid]) {
                username = this.props.users[event.userid];
            }
            if (username == null) {
                user = <span className="placeholder">anonymous account</span>;
            } else {
                user = <span>{username}</span>;
            }
        }

        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="transaction">
                    <div className="circle" />
                    PASELI Transaction
                </td>
                <td className="details">
                    { user ?
                        <div>
                            <div className="inline">User:</div>
                            <div className="inline"><a href={Link.get('viewuser', event.userid)}>{user}</a></div>
                        </div> : null
                    }
                    { this.props.arcades ?
                        <div>
                            <div className="inline">Arcade:</div>
                            <div className="inline">{this.props.arcades[event.arcadeid]}</div>
                        </div> : null
                    }
                    { event.data['pcbid'] ?
                        <div>
                            <div className="inline">PCBID:</div>
                            <pre className="inline">{event.data.pcbid}</pre>
                        </div> : null
                    }
                    <div>
                        <div className="inline">Reason:</div>
                        <pre className="inline">{event.data.reason}</pre>
                    </div>
                    <div>
                        <div className="inline">Transaction Amount:</div>
                        <pre className="inline">{event.data.delta}</pre>
                    </div>
                    { event.data['service'] && event.data['service'] != 0 ?
                        <div>
                            <div className="inline">Service PASELI Amount:</div>
                            <pre className="inline">{event.data.service}</pre>
                        </div> : null
                    }
                    <div>
                        <div className="inline">New Balance:</div>
                        <pre className="inline">{event.data.balance}</pre>
                    </div>
                </td>
            </tr>
        );
    },
});

var JubeatLeagueCourseEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        var game = this.props.versions[event.data.version];
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="scheduled">
                    <div className="circle" />
                    Generated New {game} League Course
                </td>
                <td className="details">
                    <div>Songs:</div>
                    {event.data.songs.map(function(songid) {
                        return (
                            <div>
                                <a href={Link.get('jubeatsong', songid)}>
                                    {this.props.songs[songid].artist}{this.props.songs[songid].artist ? " - " : ""}{this.props.songs[songid].name}
                                </a>
                            </div>
                        );
                    }.bind(this))}
                </td>
            </tr>
        );
    },
});

var JubeatFCChallengeEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        var game = this.props.versions[event.data.version];
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="scheduled">
                    <div className="circle" />
                    Generated New {game} Full Combo Challenge Songs
                </td>
                <td className="details">
                    <div>Challenge:</div>
                    <div>
                        <a href={Link.get('jubeatsong', event.data.today)}>
                            {this.props.songs[event.data.today].artist}{this.props.songs[event.data.today].artist ? " - " : ""}{this.props.songs[event.data.today].name}
                        </a>
                    </div>
                    {event.data.whim ?
                        <div>
                            <div>Whim:</div>
                            <div>
                                <a href={Link.get('jubeatsong', event.data.whim)}>
                                    {this.props.songs[event.data.whim].artist}{this.props.songs[event.data.whim].artist ? " - " : ""}{this.props.songs[event.data.whim].name}
                                </a>
                            </div>
                        </div> : null
                    }
                </td>
            </tr>
        );
    },
});

var JubeatRandomCourseEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        var game = this.props.versions[event.data.version];
        var charts = ["Basic", "Advanced", "Extreme"];

        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="scheduled">
                    <div className="circle" />
                    Generated New {game} Random 10s Course
                </td>
                <td className="details">
                    <div>Songs:</div>
                    {[event.data.song1, event.data.song2, event.data.song3].map(function(song) {
                        return (
                            <div>
                                <a href={Link.get('jubeatsong', song.id) + "#" + charts[song.chart]}>
                                    {this.props.songs[song.id].artist}{this.props.songs[song.id].artist ? " - " : ""}{this.props.songs[song.id].name}
                                </a> ({charts[song.chart]})
                            </div>
                        );
                    }.bind(this))}
                </td>
            </tr>
        );
    },
});

var IIDXDailyChartsEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        var game = this.props.versions[event.data.version];
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="scheduled">
                    <div className="circle" />
                    Generated New {game} Dailies
                </td>
                <td className="details">
                    <div>Songs:</div>
                    {event.data.music.map(function(songid) {
                        return (
                            <div>
                                <a href={Link.get('iidxsong', songid)}>
                                    {this.props.songs[songid].artist} - {this.props.songs[songid].name}
                                </a>
                            </div>
                        );
                    }.bind(this))}
                </td>
            </tr>
        );
    },
});

var PopnMusicCourseEvent = createReactClass({
    render: function() {
        var event = this.props.event;
        var game = this.props.versions[event.data.version];
        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="scheduled">
                    <div className="circle" />
                    Generated New {game} Weekly Course Song
                </td>
                <td className="details">
                    <div>Song:</div>
                    <div>
                        <a href={Link.get('pnmsong', event.data.song)}>
                            {this.props.songs[event.data.song].artist}{this.props.songs[event.data.song].artist ? " - " : ""}{this.props.songs[event.data.song].name}
                        </a>
                    </div>
                </td>
            </tr>
        );
    },
});

var DDRProfilePurge = createReactClass({
    render: function() {
        var event = this.props.event;
        var username = null;
        var user = null;
        if (this.props.users) {
            if (this.props.users[event.data.userid]) {
                username = this.props.users[event.data.userid];
            }
            if (username == null) {
                user = <span className="placeholder">anonymous account</span>;
            } else {
                user = <span>{username}</span>;
            }
        }

        return (
            <tr key={event.id}>
                <td><Timestamp timestamp={event.timestamp} /></td>
                <td className="profilepurge">
                    <div className="circle" />
                    DDR Ace Profile Purge
                </td>
                <td className="details">
                    { user ?
                        <div>
                            <div className="inline">User:</div>
                            <div className="inline"><a href={Link.get('viewuser', event.data.userid)}>{user}</a></div>
                        </div> : null
                    }
                    <div>Orphaned DDR Ace account was purged from the network.</div>
                </td>
            </tr>
        );
    },
});
