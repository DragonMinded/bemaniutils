/*** @jsx React.DOM */

var all_players = createReactClass({

    getInitialState: function(props) {
        return {
            players: window.players,
        };
    },

    componentDidMount: function() {
        this.refreshPlayers();
    },

    refreshPlayers: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    players: response.players,
                });
                // Refresh every 30 seconds
                setTimeout(this.refreshPlayers, 30000);
            }.bind(this)
        );
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    <Table
                        className="list players"
                        columns={[
                            {
                                name: 'Name',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return <a href={Link.get('player', userid)}>{ player.name }</a>;
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return a.name.localeCompare(b.name);
                                }.bind(this),
                            },
                            {
                                name: 'Gitadora ID',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return player.extid;
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return a.extid.localeCompare(b.extid);
                                }.bind(this),
                            },
                            {
                                name: 'GF Skills',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return (player.gf_skills / 100).toFixed(2);
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return a.gf_skills - b.gf_skills;
                                }.bind(this),
                            },
                            {
                                name: 'DM Skills',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return (player.dm_skills / 100).toFixed(2);
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return a.dm_skills - b.dm_skills;
                                }.bind(this),
                            },
                            {
                                name: 'ALL Skills',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return ((player.dm_skills + player.gf_skills) / 100).toFixed(2);
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return (a.dm_skills + a.gf_skills) - (b.dm_skills + b.gf_skills);
                                }.bind(this),
                            },
                            {
                                name: 'Play Count',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return player.plays;
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return a.plays - b.plays;
                                }.bind(this),
                                reverse: true,
                            },
                        ]}
                        rows={Object.keys(this.state.players)}
                        paginate={10}
                    />
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(all_players, null),
    document.getElementById('content')
);
