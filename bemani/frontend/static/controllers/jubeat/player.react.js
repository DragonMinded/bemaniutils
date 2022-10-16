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

    renderJubility: function(player) {
        return(
            // version == prop ( No Jubility )
            this.state.version == 10 ?
            null
            :
            // version == qubell ( No Jubility )
            this.state.version == 11 ?
            null
            :
            // version == festo
            this.state.version == 13 ?
                <LabelledSection label="Jubility">
                {(player.common_jubility+player.pick_up_jubility).toFixed(1)}
                </LabelledSection>
            :
            // Default which version >= Saucer except qubell and festo
            this.state.version >= 8 ?
                <LabelledSection label="Jubility">
                {player.jubility / 100}
                </LabelledSection>
            :
            null
        )
    },

    render: function() {
        if (this.state.player[this.state.version]) {
            var player = this.state.player[this.state.version];
            var item = Object.keys(window.versions).map(function(k){
                return window.versions[k]
            })
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
                        <LabelledSection label="Profile Created">
                            <Timestamp timestamp={player.first_play_time}/>
                        </LabelledSection>
                        <LabelledSection label="Last Played">
                            <Timestamp timestamp={player.last_play_time}/>
                        </LabelledSection>
                        <LabelledSection label="Total Rounds">
                            {player.plays}回
                        </LabelledSection>
                    </div>
                    <div className="section">
                        <LabelledSection label="Excellent Clears">
                            {player.ex_count}回
                        </LabelledSection>
                        <LabelledSection label="Full Combo Clears">
                            {player.fc_count}回
                        </LabelledSection>
                        {this.renderJubility(player)}
                    </div>
                    {this.state.version >= 12 ? <div className="section">
                        <b>
                            <a href={Link.get('jubility', null, this.state.version)}>{ window.own_profile ?
                                <span>Your Jubility Breakdown &rarr;</span> :
                                <span>{player.name}'s Jubility Breakdown &rarr;</span>
                            }</a>
                        </b>
                    </div> : null}
                    <div className="section">
                        <a href={Link.get('records')}>{ window.own_profile ?
                            <span>view your records</span> :
                            <span>view {player.name}'s records</span>
                        }</a>
                        <span className="separator">&middot;</span>
                        <a href={Link.get('scores')}>{ window.own_profile ?
                            <span>view all your scores</span> :
                            <span>view all {player.name}'s scores</span>
                        }</a>
                    </div>
                </div>
            );
        } else {
            var item = Object.keys(window.versions).map(function(k){
                return window.versions[k]
            })
            return (
                <div>
                    <div className="section">
                        <SelectVersion
                            name="version"
                            value={ item.indexOf(item[this.state.version - 1]) }
                            versions={ item }
                            onChange={function(event) {
                                var version = item.indexOf(item[event]) + 1
                                if (this.state.version == version) { return; }
                                this.setState({version: version});
                                pagenav.navigate(version);
                            }.bind(this)}
                        />
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
