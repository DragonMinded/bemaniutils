/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var profile_view = createReactClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        return {
            player: window.player,
            profiles: profiles,
            version: pagenav.getInitialState(profiles[profiles.length - 1]),
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(version) {
            this.setState({version: version});
        }.bind(this));
        this.refreshProfile();
    },

    refreshProfile: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                var profiles = Object.keys(response.player);

                this.setState({
                    player: response.player,
                    profiles: profiles,
                });
                setTimeout(this.refreshProfile, 5000);
            }.bind(this)
        );
    },

    render: function() {
        if (this.state.player[this.state.version]) {
            var player = this.state.player[this.state.version];
            return (
                <div>
                    <div className="section">
                        <h3>{player.name}'s profile</h3>
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
                        <LabelledSection label="Total Skills">{(player.gf_skills + player.dm_skills) / 100}</LabelledSection>
                        <LabelledSection label="Register Time">
                            <Timestamp timestamp={player.first_play_time}/>
                        </LabelledSection>
                        <LabelledSection label="Last Play Time">
                            <Timestamp timestamp={player.last_play_time}/>
                        </LabelledSection>
                        <LabelledSection label="Total Plays">
                            {player.plays}回
                        </LabelledSection>
                    </div>
                    <div className="section">
                        <b>
                            <a href={Link.get('skills', null, this.state.version)}>{ window.own_profile ?
                                <span>Your Play Skills &rarr;</span> :
                                <span>{player.name}'s Play Skills &rarr;</span>
                            }</a>
                        </b>
                    </div>
                    <div className="section">
                        <span className="separator">&middot;</span>
                        <a href={Link.get('scores')}>{ window.own_profile ?
                            <span>view all your scores</span> :
                            <span>view all {player.name}'s scores</span>
                        }</a>
                    </div>
                    <div>
                        {window.own_profile ? 
                            <br/>
                            : null
                        }
                    </div>
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
