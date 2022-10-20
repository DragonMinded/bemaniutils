/*** @jsx React.DOM */

var gamesettings = createReactClass({
    render: function() {
        return (
            <div>
                <div className="section">
                    Game settings that will be used for any PCBID that does not belong to an arcade.
                </div>
                <div className="section">
                    <GameSettings game_settings={window.game_settings} />
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(gamesettings, null),
    document.getElementById('content')
);
