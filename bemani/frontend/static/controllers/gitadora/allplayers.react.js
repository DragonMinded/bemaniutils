/*** @jsx React.DOM */

var all_players = React.createClass({

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
                                name: 'Player Skills',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    var player_skill = player.gf_skills / 100 + player.dm_skills / 100;
                                    return player_skill.toFixed(2);
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    var b_skill = b.gf_skills / 100 + b.dm_skills / 100;
                                    return a.extid.localeCompare(b_skill.toFixed(2));
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
