/*** @jsx React.DOM */

var valid_sorts = ['series', 'name', 'popularity'];
var valid_charts = [0, 'Gituar Basic', 'Gituar Advanced', 'Gituar Extreme', 'Gituar Master', 0, 'Drum Basic', 'Drum Advanced', 'Drum Extreme', 'Drum Master', 0, 'Bass Basic', 'Bass Advanced', 'Bass Extreme', 'Bass Master'];
/*** @jsx React.DOM */
var valid_mixes = Object.keys(window.versions).map(function(mix) {
    return (parseInt(mix) - 1).toString();
});
var valid_subsorts = [valid_mixes, false, false, valid_charts, valid_charts];
if (window.showpersonalsort) {
    valid_sorts.push('grade');
}
var pagenav = new History(valid_sorts, valid_subsorts);
var sort_names = {
    'series': 'Series',
    'name': 'Song Name',
    'popularity': 'Popularity',
    'grade': 'Score',
};
var chart_map = [0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14];

var HighScore = createReactClass({
    render: function() {
        if (!this.props.score) {
            return null;
        }

        return (
            <div className="score">
                <div>
                    <span className="label">Skills</span>
                    <span className="score">{score.points / 100}</span>
                    <span className="bolder">Music Rate:</span> {score.perc == -1 ? '-' : score.perc / 100 +'%'}
                <div>
                </div>
                    <span className="status">Score level:</span> {score.status}
                    <br/>
                    <span className="bolder">Stats:</span>
                    {score.stats.score}
                    <span> / </span>
                    {score.stats.perfect}
                    <span> / </span>
                    {score.stats.great}
                    <span> / </span>
                    {score.stats.good}
                    <span> / </span>
                    {score.stats.ok}
                    <span> / </span>
                    {score.stats.miss}
                </div>
                <div>
                    <span className="status">{this.props.score.halo}</span>
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

    getPlays: function(record) {
        if (!record) { return 0; }
        var plays = 0;
        for (var i = 0; i < 15; i++) {
            if (record[i]) { plays += record[i].plays; }
        }
        return plays;
    },

    renderDifficulty: function(songid, chart) {
        if (this.state.songs[songid].difficulties[chart] == 0) {
            return <span className="difficulty">--</span>;
        } else {
            return <span className="difficulty">{this.state.songs[songid].difficulties[chart]}</span>;
        }
    },

    renderBySeries: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            var acat = this.state.songs[a].category;
            var bcat = this.state.songs[b].category;

            if (acat == bcat) {
                return parseInt(b) - parseInt(a)
            } else {
                return bcat - acat;
            }
        }.bind(this));
        if (window.filterempty) {
            songids = songids.filter(function(songid) {
                return this.getPlays(this.state.records[songid]) > 0;
            }.bind(this));
        }
        var lastSeries = 0;
        for (var i = 0; i < songids.length; i++) {
            var curSeries = this.state.songs[songids[i]].category;
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
                                        title={ this.state.versions[-songid] }
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
                                        <tr key={(-songid).toString()}>
                                            <td className="subheader">{ this.state.versions[-songid] }</td>
                                            <td className="subheader">Gituar Basic</td>
                                            <td className="subheader">Gituar Advanced</td>
                                            <td className="subheader">Gituar Extreme</td>
                                            <td className="subheader">Gituar Master</td>
                                            <td className="subheader">Drum Basic</td>
                                            <td className="subheader">Drum Advanced</td>
                                            <td className="subheader">Drum Extreme</td>
                                            <td className="subheader">Drum Master</td>
                                            <td className="subheader">Bass Basic</td>
                                            <td className="subheader">Bass Advanced</td>
                                            <td className="subheader">Bass Extreme</td>
                                            <td className="subheader">Bass Master</td>
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
                                                <a href={Link.get('individual_score', songid)}>
                                                    <div className="songname">{ this.state.songs[songid].name }</div>
                                                    <div className="songartist">{ this.state.songs[songid].artist }</div>
                                                </a>
                                                <div className="songdifficulties">
                                                    <span>Gituar </span>
                                                    {this.renderDifficulty(songid, 1)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 2)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 3)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 4)}
                                                </div>
                                                <div className="songdifficulties">
                                                    <span>Drum </span>
                                                    {this.renderDifficulty(songid, 6)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 7)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 8)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 9)}
                                                </div>
                                                <div className="songdifficulties">
                                                    <span>Bass </span>
                                                    {this.renderDifficulty(songid, 11)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 12)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 13)}
                                                    <span> / </span>
                                                    {this.renderDifficulty(songid, 14)}
                                                </div>
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
                                            <td className={difficulties[6] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={6}
                                                    score={records[6]}
                                                />
                                            </td>
                                            <td className={difficulties[7] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={7}
                                                    score={records[7]}
                                                />
                                            </td>
                                            <td className={difficulties[8] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={8}
                                                    score={records[8]}
                                                />
                                            </td>
                                            <td className={difficulties[9] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={9}
                                                    score={records[9]}
                                                />
                                            </td>
                                            <td className={difficulties[11] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={11}
                                                    score={records[11]}
                                                />
                                            </td>
                                            <td className={difficulties[12] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={12}
                                                    score={records[12]}
                                                />
                                            </td>
                                            <td className={difficulties[13] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={13}
                                                    score={records[13]}
                                                />
                                            </td>
                                            <td className={difficulties[14] > 0 ? "" : "nochart"}>
                                                <HighScore
                                                    players={this.state.players}
                                                    songid={songid}
                                                    chart={14}
                                                    score={records[14]}
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

    renderByPercent: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            // Grab records for this song
            var ar = this.state.records[a];
            var br = this.state.records[b];
            var ac = null;
            var bc = null;
            var as = 0;
            var bs = 0;

            // Fill in record for current chart only if it exists
            if (ar) { ac = ar[window.chart_map[this.state.subtab]]; }
            if (br) { bc = br[window.chart_map[this.state.subtab]]; }

            // Get the lamp only if the current chart exisrts
            if (ac) { as = ac.points / 100; }
            if (bc) { bs = bc.points / 100; }

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

    renderByClearLamp: function() {
        var songids = Object.keys(this.state.songs).sort(function(a, b) {
            // Grab records for this song
            var ar = this.state.records[a];
            var br = this.state.records[b];
            var ac = null;
            var bc = null;
            var al = 0;
            var bl = 0;

            // Fill in record for current chart only if it exists
            if (ar) { ac = ar[window.chart_map[this.state.subtab]]; }
            if (br) { bc = br[window.chart_map[this.state.subtab]]; }

            // Get the lamp only if the current chart exisrts
            if (ac) { al = ac.lamp; }
            if (bc) { bl = bc.lamp; }

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
            <table className="list records">
                <thead>
                    <tr>
                        <th className="subheader">Song</th>
                        <th className="subheader">Gituar Basic</th>
                        <th className="subheader">Gituar Advanced</th>
                        <th className="subheader">Gituar Extreme</th>
                        <th className="subheader">Gituar Master</th>
                        <th className="subheader">Drum Basic</th>
                        <th className="subheader">Drum Advanced</th>
                        <th className="subheader">Drum Extreme</th>
                        <th className="subheader">Drum Master</th>
                        <th className="subheader">Bass Basic</th>
                        <th className="subheader">Bass Advanced</th>
                        <th className="subheader">Bass Extreme</th>
                        <th className="subheader">Bass Master</th>
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

                        var difficulties = this.state.songs[songid].difficulties;
                        var plays = this.getPlays(records);
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
                                        <span>Gituar </span>
                                        {this.renderDifficulty(songid, 1)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 2)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 3)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 4)}
                                    </div>
                                    <div className="songdifficulties">
                                        <span>Drum </span>
                                        {this.renderDifficulty(songid, 6)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 7)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 8)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 9)}
                                    </div>
                                    <div className="songdifficulties">
                                        <span>Bass </span>
                                        {this.renderDifficulty(songid, 11)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 12)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 13)}
                                        <span> / </span>
                                        {this.renderDifficulty(songid, 14)}
                                    </div>
                                    { showplays ? <div className="songplays">#{index + 1} - {plays}{plays == 1 ? ' play' : ' plays'}</div> : null }
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
                                <td className={difficulties[6] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={6}
                                        score={records[6]}
                                    />
                                </td>
                                <td className={difficulties[7] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={7}
                                        score={records[7]}
                                    />
                                </td>
                                <td className={difficulties[8] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={8}
                                        score={records[8]}
                                    />
                                </td>
                                <td className={difficulties[9] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={9}
                                        score={records[9]}
                                    />
                                </td>
                                <td className={difficulties[11] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={11}
                                        score={records[11]}
                                    />
                                </td>
                                <td className={difficulties[12] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={12}
                                        score={records[12]}
                                    />
                                </td>
                                <td className={difficulties[13] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={13}
                                        score={records[13]}
                                    />
                                </td>
                                <td className={difficulties[14] > 0 ? "" : "nochart"}>
                                    <HighScore
                                        players={this.state.players}
                                        songid={songid}
                                        chart={14}
                                        score={records[14]}
                                    />
                                </td>
                            </tr>
                        );
                    }.bind(this))}
                </tbody>
                <tfoot>
                    <tr>
                        <td colSpan={10}>
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
            data = this.renderByPercent();
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
