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
                                name: 'Jubeat ID',
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
                            {
                                name: 'Jubility',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    if (player.common_jubility != 0 || player.pick_up_jubility != 0) {
                                        return (player.common_jubility + player.pick_up_jubility).toFixed(1);
                                    } else if (player.jubility != 0) {
                                        return player.jubility / 100
                                    } else {
                                        return 0
                                    }
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    if (a.common_jubility != 0 || a.pick_up_jubility != 0)
                                        var ajub = a.common_jubility+a.pick_up_jubility;
                                    else
                                        var ajub = a.jubility / 100;
                                    if (b.common_jubility != 0 || b.pick_up_jubility != 0)
                                        var bjub = b.common_jubility+b.pick_up_jubility;
                                    else
                                        var bjub = b.jubility / 100;
                                    return ajub-bjub;
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
