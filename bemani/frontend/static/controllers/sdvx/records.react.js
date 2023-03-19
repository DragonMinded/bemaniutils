/*** @jsx React.DOM */

var valid_sorts = ['series', 'name', 'popularity'];
var valid_charts = ['Novice', 'Advanced', 'Exhaust', 'Infinite', 'Maximum'];
var valid_mixes = Object.keys(window.versions);
var valid_subsorts = [valid_mixes, false, false, valid_charts, valid_charts];
if (window.showpersonalsort) {
    valid_sorts.push('grade');
    valid_sorts.push('clear');
}
var pagenav = new History(valid_sorts, valid_subsorts);
var sort_names = {
    'series': 'Series',
    'name': 'Song Name',
    'popularity': 'Popularity',
    'grade': 'Score',
    'clear': 'Clear Type',
};

var HighScore = createReactClass({
    render: function() {
        if (!this.props.score) {
            return null;
        }
        has_stats = (
            this.props.score.stats.critical > 0 ||
            this.props.score.stats.near > 0 ||
            this.props.score.stats.error > 0
        );

        return (
            <div className="score">
                <div>
                    <span className="grade">{this.props.score.grade}</span>
                    <span className="label">Score</span>
                    <span className="score">{this.props.score.points}</span>
                    <span className="label">Combo</span>
                    <span className="score">{this.props.score.combo < 0 ? '-' : this.props.score.combo}</span>
                </div>
                {has_stats ? <div title="critical / near / error">
                    {this.props.score.stats.critical}
                <span> / </span>
                    {this.props.score.stats.near}
                <span> / </span>
                    {this.props.score.stats.error}
                </div> : null}
                <div>
                    <span className="status">{this.props.score.clear_type}</span>
                </div>
                { this.props.score.userid && window.shownames ?
                    <div><a href={Link.get('player', this.props.score.userid)}>{
                        this.props.players[this.props.score.userid].name
                    }</a></div> : null
                }
            </div>
        );
    },
});

var network_records = createReactClass({

    sortRecords: function(records) {
        var sorted_records = {};

        records.forEach(function(record) {
            if (!(record.songid in sorted_records)) {
                sorted_records[record.songid] = {}
            }
            sorted_records[record.songid][record.chart] = record;
        });

        return sorted_records;
    },

    getInitialState: function(props) {
        return {
            songs: window.songs,
            records: this.sortRecords(window.records),
            players: window.players,
            versions: window.versions,
            sort: pagenav.getInitialState('series', '0'),
            subtab: this.getSubIndex('series', pagenav.getInitialSubState('series', '0')),
            offset: 0,
            limit: 10,
        };
    },

    getSubIndex: function(sort, subsort) {
        var subtab = 0;
        window.valid_sorts.forEach(function(potential, index) {
            if (window.valid_subsorts[index]) {
                window.valid_subsorts[index].forEach(function(subpotential, subindex) {
                    if (subpotential == subsort) {
                        subtab = subindex;
                    }
                }.bind(this));
            }
        }.bind(this));
        return subtab;
    },

    componentDidMount: function() {
        pagenav.onChange(function(sort, subsort) {
            var subtab = this.getSubIndex(sort, subsort);
            this.setState({sort: sort, offset: 0, subtab: subtab});
        }.bind(this));
        this.refreshRecords();
    },

    refreshRecords: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    records: this.sortRecords(response.records),
                    players: response.players,
                });
                // Refresh every 15 seconds
                setTimeout(this.refreshRecords, 15000);
            }.bind(this)
        );
    },

    renderDifficulty: function(songid, chart) {
        if (this.state.songs[songid].difficulties[chart] == 0) {
            return <span className="difficulty">--</span>;
        } else {
            return <span className="difficulty">{this.state.songs[songid].difficulties[chart]}</span>;
        }
    },

    getPlays: function(record) {
        if (!record) { return 0; }
        var plays = 0;
        for (var i = 0; i < 4; i++) {
            if (record[i]) { plays += record[i].plays; }
        }
        return plays;
    },

    renderBySeries: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            var ac = this.state.songs[a].category;
            var bc = this.state.songs[b].category;
            return parseInt(bc) - parseInt(ac);
        }.bind(this));
        if (window.filterempty) {
            songids = songids.filter(function(songid) {
                return this.getPlays(this.state.records[songid]) > 0;
            }.bind(this));
        }
        var lastSeries = 0;
        for (var i = 0; i < songids.length; i++) {
            var curSeries = parseInt(this.state.songs[songids[i]].category) + 1;
            if (curSeries != lastSeries) {
                lastSeries = curSeries;
                songids.splice(i, 0, -curSeries);
            }
        }

        if (songids.length == 0) {
            return (
                <div>
                    No records to display!
                </div>
            );
        }

        var paginate = false;
        var curpage = -1;
        var curbutton = -1;
        if (songids.length > 99) {
            // Arbitrary limit for perf reasons
            paginate = true;
        }

        return (
            <>
                { paginate ?
                    <div className="section" key="paginatebuttons">
                        {songids.map(function(songid) {
                            if (songid < 0) {
                                curbutton = curbutton + 1;
                                var subtab = curbutton;
                                return (
                                    <Nav
                                        title={ this.state.versions[(-songid) - 1] }
                                        active={ subtab == this.state.subtab }
                                        onClick={function(event) {
                                            if (this.state.subtab == subtab) { return; }
                                            this.setState({subtab: subtab, offset: 0});
                                            pagenav.navigate(this.state.sort, window.valid_mixes[subtab]);
                                        }.bind(this)}
                                    />
                                );
                            } else {
                                return null;
                            }
                        }.bind(this))}
                    </div> :
                    null
                }
                <div className="section" key="contents">
                    <table className="list records">
                        <thead></thead>
                        <tbody>
                            {songids.map(function(songid) {
                                if (songid < 0) {
                                    // This is a series header
                                    curpage = curpage + 1;
                                    if (paginate && curpage != this.state.subtab) { return null; }

                                    return (
                                        <tr key={songid.toString()} className="header">
                                            <td className="subheader">{
                                                !paginate ? this.state.versions[(-songid) - 1] : "Song / Artist / Difficulties"
                                            }</td>
                                            <td className="subheader">Novice</td>
                                            <td className="subheader">Advanced</td>
                                            <td className="subheader">Exhaust</td>
                                            <td className="subheader">Infinite</td>
                                            <td className="subheader">Maximum</td>
                                        </tr>
                                    );
                                } else {
                                    if (paginate && curpage != this.state.subtab) { return null; }

                                    var records = this.state.records[songid];
                                    if (!records) {
                                        records = {};
                                    }

                                    var difficulties = this.state.songs[songid].difficulties;
                                    return (
                                        <tr key={songid.toString()}>
                                            <td className="center">
                                                <div>
                                                    <a href={Link.get('individual_score', songid)}>
                                                        <div className="songname">{ this.state.songs[songid].name }</div>
                                                        <div className="songartist">{ this.state.songs[songid].artist }</div>
                                                    </a>
                                                </div>
                                                <div className="songdifficulties">
                                                    {this.renderDifficulty(songid, 0)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 1)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 2)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 3)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 4)}
                                                </div>
                                            </td>
                                            <td className={difficulties[0] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={0}
                                                    score={records[0]}
                                                />
                                            </td>
                                            <td className={difficulties[1] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={1}
                                                    score={records[1]}
                                                />
                                            </td>
                                            <td className={difficulties[2] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={2}
                                                    score={records[2]}
                                                />
                                            </td>
                                            <td className={difficulties[3] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={3}
                                                    score={records[3]}
                                                />
                                            </td>
                                            <td className={difficulties[4] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={4}
                                                    score={records[4]}
                                                />
                                            </td>
                                        </tr>
                                    );
                                }
                            }.bind(this))}
                        </tbody>
                    </table>
                </div>
            </>
        );
    },

    renderByName: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            var an = this.state.songs[a].name;
            var bn = this.state.songs[b].name;
            var c = an.localeCompare(bn);
            if (c == 0) {
                return parseInt(a) - parseInt(b)
            } else {
                return c;
            }
        }.bind(this));
        if (window.filterempty) {
            songids = songids.filter(function(songid) {
                return this.getPlays(this.state.records[songid]) > 0;
            }.bind(this));
        }

        return this.renderBySongIDList(songids, false);
    },

    renderByPopularity: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            var ap = this.getPlays(this.state.records[a]);
            var bp = this.getPlays(this.state.records[b]);
            if (bp == ap) {
                return parseInt(a) - parseInt(b)
            } else {
                return bp - ap;
            }
        }.bind(this));
        if (window.filterempty) {
            songids = songids.filter(function(songid) {
                return this.getPlays(this.state.records[songid]) > 0;
            }.bind(this));
        }

        return this.renderBySongIDList(songids, true);
    },

    renderByScore: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            // Grab records for this song
            var ar = this.state.records[a];
            var br = this.state.records[b];
            var ac = null;
            var bc = null;
            var as = 0;
            var bs = 0;

            // Fill in record for current chart only if it exists
            if (ar) { ac = ar[this.state.subtab]; }
            if (br) { bc = br[this.state.subtab]; }
            if (ac) { as = ac.points; }
            if (bc) { bs = bc.points; }

            if (bs == as) {
                return parseInt(a) - parseInt(b);
            } else {
                return bs - as;
            }
        }.bind(this));
        if (window.filterempty) {
            songids = songids.filter(function(songid) {
                return this.getPlays(this.state.records[songid]) > 0;
            }.bind(this));
        }

        return (
            <>
                <div className="section">
                    {window.valid_charts.map(function(chartname, index) {
                        return (
                            <Nav
                                title={ chartname }
                                active={ this.state.subtab == index }
                                onClick={function(event) {
                                    if (this.state.subtab == index) { return; }
                                    this.setState({subtab: index, offset: 0});
                                    pagenav.navigate(this.state.sort, window.valid_charts[index]);
                                }.bind(this)}
                            />
                        );
                    }.bind(this))}
                </div>
                { this.renderBySongIDList(songids, false) }
            </>
        );
    },

    renderByClearType: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            // Grab records for this song
            var ar = this.state.records[a];
            var br = this.state.records[b];
            var ac = null;
            var bc = null;
            var al = 0;
            var bl = 0;

            // Fill in record for current chart only if it exists
            if (ar) { ac = ar[this.state.subtab]; }
            if (br) { bc = br[this.state.subtab]; }
            if (ac) { al = ac.medal; }
            if (bc) { bl = bc.medal; }

            if (al == bl) {
                return parseInt(a) - parseInt(b)
            } else {
                return bl - al;
            }
        }.bind(this));
        if (window.filterempty) {
            songids = songids.filter(function(songid) {
                return this.getPlays(this.state.records[songid]) > 0;
            }.bind(this));
        }

        return (
            <>
                <div className="section">
                    {window.valid_charts.map(function(chartname, index) {
                        return (
                            <Nav
                                title={ chartname }
                                active={ this.state.subtab == index }
                                onClick={function(event) {
                                    if (this.state.subtab == index) { return; }
                                    this.setState({subtab: index, offset: 0});
                                    pagenav.navigate(this.state.sort, window.valid_charts[index]);
                                }.bind(this)}
                            />
                        );
                    }.bind(this))}
                </div>
                { this.renderBySongIDList(songids, false) }
            </>
        );
    },

    renderBySongIDList: function(songids, showplays) {
        return (
            <div className="section">
                <table className="list records">
                    <thead>
                        <tr>
                            <th className="subheader">Song / Artist / Difficulties</th>
                            <th className="subheader">Novice</th>
                            <th className="subheader">Advanced</th>
                            <th className="subheader">Exhaust</th>
                            <th className="subheader">Infinite</th>
                            <th className="subheader">Maximum</th>
                        </tr>
                    </thead>
                    <tbody>
                        {songids.map(function(songid, index) {
                            if (index < this.state.offset || index >= this.state.offset + this.state.limit) {
                                return null;
                            }

                            var records = this.state.records[songid];
                            if (!records) {
                                records = {};
                            }

                            var plays = this.getPlays(records);
                            var difficulties = this.state.songs[songid].difficulties;
                            return (
                                <tr key={songid.toString()}>
                                    <td className="center">
                                        <div>
                                            <a href={Link.get('individual_score', songid)}>
                                                <div className="songname">{ this.state.songs[songid].name }</div>
                                                <div className="songartist">{ this.state.songs[songid].artist }</div>
                                            </a>
                                        </div>
                                        <div className="songdifficulties">
                                            {this.renderDifficulty(songid, 0)}
                                            <span> / </span>
                                            {this.renderDifficulty(songid, 1)}
                                            <span> / </span>
                                            {this.renderDifficulty(songid, 2)}
                                            <span> / </span>
                                            {this.renderDifficulty(songid, 3)}
                                            <span> / </span>
                                            {this.renderDifficulty(songid, 4)}
                                        </div>
                                        { showplays ? <div className="songplays">#{index + 1} - {plays}{plays == 1 ? ' play' : ' plays'}</div> : null }
                                    </td>
                                    <td className={difficulties[0] > 0 ? "" : "nochart"}>
                                        <HighScore
                                            players={this.state.players}
                                            songid={songid}
                                            chart={0}
                                            score={records[0]}
                                        />
                                    </td>
                                    <td className={difficulties[1] > 0 ? "" : "nochart"}>
                                        <HighScore
                                            players={this.state.players}
                                            songid={songid}
                                            chart={1}
                                            score={records[1]}
                                        />
                                    </td>
                                    <td className={difficulties[2] > 0 ? "" : "nochart"}>
                                        <HighScore
                                            players={this.state.players}
                                            songid={songid}
                                            chart={2}
                                            score={records[2]}
                                        />
                                    </td>
                                    <td className={difficulties[3] > 0 ? "" : "nochart"}>
                                        <HighScore
                                            players={this.state.players}
                                            songid={songid}
                                            chart={3}
                                            score={records[3]}
                                        />
                                    </td>
                                    <td className={difficulties[4] > 0 ? "" : "nochart"}>
                                        <HighScore
                                            players={this.state.players}
                                            songid={songid}
                                            chart={4}
                                            score={records[4]}
                                        />
                                    </td>
                                </tr>
                            );
                        }.bind(this))}
                    </tbody>
                    <tfoot>
                        <tr>
                            <td colSpan={6}>
                                { this.state.offset > 0 ?
                                    <Prev onClick={function(event) {
                                         var page = this.state.offset - this.state.limit;
                                         if (page < 0) { page = 0; }
                                         this.setState({offset: page});
                                    }.bind(this)}/> : null
                                }
                                { (this.state.offset + this.state.limit) < songids.length ?
                                    <Next style={ {float: 'right'} } onClick={function(event) {
                                         var page = this.state.offset + this.state.limit;
                                         if (page >= songids.length) { return }
                                         this.setState({offset: page});
                                    }.bind(this)}/> :
                                    null
                                }
                            </td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        );
    },

    render: function() {
        var data = null;
        if (this.state.sort == 'series') {
            data = this.renderBySeries();
        } else if (this.state.sort == 'popularity') {
            data = this.renderByPopularity();
        } else if (this.state.sort == 'name') {
            data = this.renderByName();
        } else if (this.state.sort == 'grade') {
            data = this.renderByScore();
        } else if (this.state.sort == 'clear') {
            data = this.renderByClearType();
        }

        return (
            <div>
                <div className="section">
                    { window.valid_sorts.map(function(sort, index) {
                        return (
                            <Nav
                                title={"Records Sorted by " + window.sort_names[sort]}
                                active={this.state.sort == sort}
                                onClick={function(event) {
                                    if (this.state.sort == sort) { return; }
                                    this.setState({sort: sort, offset: 0, subtab: 0});
                                    pagenav.navigate(sort, window.valid_subsorts[index][0]);
                                }.bind(this)}
                            />
                        );
                    }.bind(this)) }
                </div>
                <div className="section">
                    {data}
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(network_records, null),
    document.getElementById('content')
);
