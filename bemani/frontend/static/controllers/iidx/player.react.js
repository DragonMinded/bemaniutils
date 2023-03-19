/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var profile_view = createReactClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        return {
            player: window.player,
            profiles: profiles,
            sp_rival: window.sp_rival,
            dp_rival: window.dp_rival,
            version: pagenav.getInitialState(profiles[profiles.length - 1]),
            updating_rivals: false,
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(version) {
            this.setState({version: version});
        }.bind(this));
        this.refreshProfile();
    },

    refreshProfile: function(skip_timeout) {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                var profiles = Object.keys(response.player);

                this.setState({
                    player: response.player,
                    profiles: profiles,
                    sp_rival: response.sp_rival,
                    dp_rival: response.dp_rival,
                    updating_rivals: false,
                });
                if (skip_timeout) {
                    // Don't refresh, we were called from rival code
                } else {
                    // Refresh every 5 seconds to show live rival updating
                    setTimeout(this.refreshProfile, 5000);
                }
            }.bind(this)
        );
    },

    addRival: function(event, type) {
        this.setState({updating_rivals: true});
        AJAX.post(
            Link.get('addrival'),
            {
                version: this.state.version,
                type: type,
                userid: window.playerid,
            },
            function(response) {
                this.refreshProfile(true);
            }.bind(this)
        );
        event.preventDefault();
    },

    removeRival: function(event, type, userid) {
        this.setState({updating_rivals: true});
        AJAX.post(
            Link.get('removerival'),
            {
                version: this.state.version,
                type: type,
                userid: window.playerid,
            },
            function(response) {
                this.refreshProfile(true);
            }.bind(this)
        );
        event.preventDefault();
    },

    render: function() {
        if (this.state.player[this.state.version]) {
            var player = this.state.player[this.state.version];
            return (
                <div>
                    <div className="section">
                        <h3>dj {player.name}'s profile</h3>
                        {this.state.profiles.map(function(version) {
                            return (
                                <Nav
                                    title={window.versions[version]}
                                    active={this.state.version == version}
                                    onClick={function(event) {
                                        if (this.state.version == version) { return; }
                                        this.setState({version: version});
                                        pagenav.navigate(version);
                                    }.bind(this)}
                                />
                            );
                        }.bind(this))}
                    </div>
                    <div className="section">
                        <LabelledSection label="User ID">{player.extid}</LabelledSection>
                        <LabelledSection label="Profile Created">
                            <Timestamp timestamp={player.first_play_time}/>
                        </LabelledSection>
                        <LabelledSection label="Last Played">
                            <Timestamp timestamp={player.last_play_time}/>
                        </LabelledSection>
                    </div>
                    <div className="section">
                        <LabelledSection className="centered padded filled" label="SP Stats">
                            <div>{player.sdan}</div>
                            <div>{player.sdjp} DJ POINT</div>
                            <div>{player.sp}回</div>
                        </LabelledSection>
                        <LabelledSection className="centered padded filled" label="DP Stats">
                            <div>{player.ddan}</div>
                            <div>{player.ddjp} DJ POINT</div>
                            <div>{player.dp}回</div>
                        </LabelledSection>
                    </div>
                    <div className="section">
                        <a href={Link.get('records')}>{ window.own_profile ?
                            <span>view your records</span> :
                            <span>view dj {player.name}'s records</span>
                        }</a>
                        <span className="separator">&middot;</span>
                        <a href={Link.get('scores')}>{ window.own_profile ?
                            <span>view all your scores</span> :
                            <span>view all dj {player.name}'s scores</span>
                        }</a>
                    </div>
                    { window.own_profile ? null :
                        <div className="section">
                            { player.sp_rival ?
                                <Delete
                                    title="Remove SP Rival"
                                    onClick={function(event) {
                                        this.removeRival(event, 'sp_rival');
                                    }.bind(this)}
                                /> :
                                <Add
                                    title="Add SP Rival"
                                    onClick={function(event) {
                                        this.addRival(event, 'sp_rival');
                                    }.bind(this)}
                                />
                            }
                            { player.dp_rival ?
                                <Delete
                                    title="Remove DP Rival"
                                    onClick={function(event) {
                                        this.removeRival(event, 'dp_rival');
                                    }.bind(this)}
                                /> :
                                <Add
                                    title="Add DP Rival"
                                    onClick={function(event) {
                                        this.addRival(event, 'dp_rival');
                                    }.bind(this)}
                                />
                            }
                            { this.state.updating_rivals ?
                                <img className="loading" src={Link.get('static', window.assets + 'loading-16.gif')} /> : null
                            }
                        </div>
                    }
                </div>
            );
        } else {
            return (
                <div>
                    <div className="section">
                        {this.state.profiles.map(function(version) {
                            return (
                                <Nav
                                    title={window.versions[version]}
                                    active={this.state.version == version}
                                    onClick={function(event) {
                                        if (this.state.version == version) { return; }
                                        this.setState({version: version});
                                        pagenav.navigate(version);
                                    }.bind(this)}
                                />
                            );
                        }.bind(this))}
                    </div>
                    <div className="section">
                        This player has no profile for {window.versions[this.state.version]}!
                    </div>
                </div>
            );
        }
    },
});

ReactDOM.render(
    React.createElement(profile_view, null),
    document.getElementById('content')
);
