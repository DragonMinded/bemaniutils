/*** @jsx React.DOM */

var valid_versions = Object.keys(window.rivals);
var pagenav = new History(valid_versions);

var rivals_view = React.createClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.rivals);
        var version = pagenav.getInitialState(profiles[profiles.length - 1]);
        return {
            rivals: window.rivals,
            players: window.players,
            profiles: profiles,
            version: version,
            term: "",
            results: {},
            searching: false,
            offset: 0,
            limit: 5,
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(version) {
            this.setState({version: version, offset: 0});
        }.bind(this));
        this.refreshRivals();
    },

    refreshRivals: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    rivals: response.rivals,
                    players: response.players,
                });
				setTimeout(this.refreshRivals, 5000);
            }.bind(this)
        );
    },

    searchForPlayers: function(event) {
        this.setState({searching: true});
        AJAX.post(
            Link.get('search'),
            {
                version: this.state.version,
                term: this.state.term,
            },
            function(response) {
                this.setState({
                    results: response.results,
                    searching: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    addRival: function(event, type, userid) {
        AJAX.post(
            Link.get('addrival'),
            {
                version: this.state.version,
                type: type,
                userid: userid,
            },
            function(response) {
                this.setState({
                    rivals: response.rivals,
                    players: response.players,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    removeRival: function(event, type, userid) {
        AJAX.post(
            Link.get('removerival'),
            {
                version: this.state.version,
                type: type,
                userid: userid,
            },
            function(response) {
                this.setState({
                    rivals: response.rivals,
                    players: response.players,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    addSPDPRivals: function(userid) {
        if (userid == window.userid) {
            return null;
        }

        var gf_avail = true;
        var dm_avail = true;
        var gf_count = 0;
        var dm_count = 0;
        var current_rivals = this.state.rivals[this.state.version];
        for (var i = 0; i < current_rivals.length; i++) {
            if (current_rivals[i].type == 'gf_rival') { gf_count++; }
            if (current_rivals[i].type == 'dm_rival') { dm_count++; }
            if (current_rivals[i].userid == userid) {
                if (current_rivals[i].type == 'gf_rival') { gf_avail = false; }
                if (current_rivals[i].type == 'dm_rival') { dm_avail = false; }
            }
        }

        if (gf_count >= 5) { gf_avail = false; }
        if (dm_count >= 5) { dm_avail = false; }

        return (
            <span>
                {gf_avail ?
                    <Add
                        title="Add GuitarFreaks Rival"
                        onClick={function(event) {
                            this.addRival(event, 'gf_rival', userid);
                        }.bind(this)}
                    /> :
                    null
                }
                {dm_avail ?
                    <Add
                        title="Add DrumMania Rival"
                        onClick={function(event) {
                            this.addRival(event, 'dm_rival', userid);
                        }.bind(this)}
                    /> :
                    null
                }
            </span>
        );
    },

    render: function() {
        if (this.state.rivals[this.state.version]) {
            var rivals = this.state.rivals[this.state.version];
            var resultlength = 0;
            Object.keys(this.state.results).map(function(userid, index) {
                var player = this.state.results[userid][this.state.version];
                if (player) { resultlength++; }
            }.bind(this));
            return (
                <div>
                    <div className="section">
                        <h3>Rivals</h3>
                        {this.state.profiles.map(function(version) {
                            return (
                                <Nav
                                    title={window.versions[version]}
                                    active={this.state.version == version}
                                    onClick={function(event) {
                                        if (this.state.version == version) { return; }
                                        this.setState({
                                            version: version,
                                            offset: 0,
                                        });
                                        pagenav.navigate(version);
                                    }.bind(this)}
                                />
                            );
                        }.bind(this))}
                    </div>
                    <div className="section">
                        <form onSubmit={this.searchForPlayers}>
                            <label for="search">Name or GITADORA ID:</label>
                            <br />
                            <input
                                type="text"
                                className="inline"
                                maxlength="9"
                                value={this.state.term}
                                onChange={function(event) {
                                    var value = event.target.value.toUpperCase();
                                    var intRegex = /^[-&$#\\.\\?\\*!A-Z0-9]*$/;
                                    // Normally, names are <= 6 characters, but we allow GITADORA IDs here too
                                    if (value.length <= 9 && intRegex.test(value)) {
                                        this.setState({term: value});
                                    }
                                }.bind(this)}
                                name="search"
                            />
                            <input type="submit" value="search" />
                            { this.state.searching ?
                                <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                                null
                            }
                        </form>
                        {resultlength > 0 ?
                            <table className="list players">
                                <thead>
                                    <tr>
                                        <th>Name</th>
                                        <th>Gitadora ID</th>
                                        <th className="action"></th>
                                    </tr>
                                </thead>
                                <tbody>{
                                    Object.keys(this.state.results).map(function(userid, index) {
                                        if (index < this.state.offset || index >= this.state.offset + this.state.limit) {
                                            return null;
                                        }
                                        var player = this.state.results[userid][this.state.version];
                                        if (!player) { return null; }

                                        return (
                                            <tr>
                                                <td><Rival userid={userid} player={player} /></td>
                                                <td>{ player.extid }</td>
                                                <td className="edit">{this.addSPDPRivals(userid)}</td>
                                            </tr>
                                        );
                                    }.bind(this))
                                }</tbody>
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
                                            { (this.state.offset + this.state.limit) < resultlength ?
                                                <Next style={ {float: 'right'} } onClick={function(event) {
                                                     var page = this.state.offset + this.state.limit;
                                                     if (page >= resultlength) { return; }
                                                     this.setState({offset: page});
                                                }.bind(this)}/> : null
                                            }
                                        </td>
                                    </tr>
                                </tfoot>
                            </table> :
                            <div className="placeholder">No players match the specified search.</div>
                        }
                    </div>
                    {['gf_rival', 'dm_rival'].map(function(rival_type) {
                        var type = '';
                        if (rival_type == 'gf_rival') {
                            type = 'GuitarFreaks';
                        } else {
                            type = 'DrumMania';
                        }

                        return (
                            <div className="section">
                                <h3>{type} Rivals</h3>
                                <table className="list players">
                                    <thead>
                                        <tr>
                                            <th>Name</th>
                                            <th>Gitadora ID</th>
                                            <th className="action"></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {this.state.rivals[this.state.version].map(function(rival, index) {
                                            if (rival.type != rival_type) { return null; }
                                            var player = this.state.players[rival.userid][this.state.version];
                                            return (
                                                <tr>
                                                    <td><Rival userid={rival.userid} player={player} /></td>
                                                    <td>{ player.extid }</td>
                                                    <td className="edit">
                                                        <Delete
                                                            title="Remove Rival"
                                                            onClick={function(event) {
                                                                this.removeRival(event, rival_type, rival.userid);
                                                            }.bind(this)}
                                                        />
                                                    </td>
                                                </tr>
                                            );
                                        }.bind(this))}
                                    </tbody>
                                </table>
                            </div>
                        );
                    }.bind(this))}
                </div>
            );
        } else {
            return (
                <div>
                    <div className="section">
                        You have no profile for {window.versions[this.state.version]}!
                    </div>
                    <div className="section">
                        {this.state.profiles.map(function(version) {
                            return (
                                <Nav
                                    title={window.versions[version]}
                                    active={this.state.version == version}
                                    onClick={function(event) {
                                        if (this.state.version == version) { return; }
                                        this.setState({version: version, offset: 0});
                                        pagenav.navigate(version);
                                    }.bind(this)}
                                />
                            );
                        }.bind(this))}
                    </div>
                </div>
            );
        }
    },
});

ReactDOM.render(
    React.createElement(rivals_view, null),
    document.getElementById('content')
);
