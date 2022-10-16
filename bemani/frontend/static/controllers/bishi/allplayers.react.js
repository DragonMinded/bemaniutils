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
                                name: 'BishiBashi ID',
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
                                name: 'Total Rounds',
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
                                name: 'Region',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return player.shop_area;
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return a.shop_area.localeCompare(b.shop_area);
                                }.bind(this),
                            },
                            {
                                name: 'Arcade',
                                render: function(userid) {
                                    var player = this.state.players[userid];
                                    return player.shop;
                                }.bind(this),
                                sort: function(aid, bid) {
                                    var a = this.state.players[aid];
                                    var b = this.state.players[bid];
                                    return a.shop.localeCompare(b.shop);
                                }.bind(this),
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
