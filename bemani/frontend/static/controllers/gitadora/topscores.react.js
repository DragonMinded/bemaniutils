/*** @jsx React.DOM */

var valid_charts = [0, 'Gituar Basic', 'Gituar Advanced', 'Gituar Extreme', 'Gituar Master', 0, 'Drum Basic', 'Drum Advanced', 'Drum Extreme', 'Drum Master', 0,'Bass Basic', 'Bass Advanced', 'Bass Extreme', 'Bass Master'].filter(function(val, index) {
    return window.difficulties[index] > 0;
});

var pagenav = new History(valid_charts);

var top_scores = createReactClass({

    sortTopScores: function(topscores) {
        var newscores = [[], [], [], [], [], [], [], [], [], [], [], [], [], [], []];
        topscores.map(function(score) {
            newscores[score.chart].push(score);
        }.bind(this));
        return newscores;
    },

    getInitialState: function(props) {
        return {
            topscores: this.sortTopScores(window.topscores),
            players: window.players,
            chart: pagenav.getInitialState(valid_charts[0]),
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(chart) {
            this.setState({chart: chart});
        }.bind(this));
        this.refreshScores();
    },

    refreshScores: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    topscores: this.sortTopScores(response.topscores),
                    players: response.players,
                });
                // Refresh every 15 seconds
                setTimeout(this.refreshScores, 15000);
            }.bind(this)
        );
    },

    convertChart: function(chart) {
        switch(chart) {
            case 'Gituar Basic':
                return 1;
            case 'Gituar Advanced':
                return 2;
            case 'Gituar Extreme':
                return 3;
            case 'Gituar Master':
                return 4;
            case 'Drum Basic':
                return 6;
            case 'Drum Advanced':
                return 7;
            case 'Drum Extreme':
                return 8;
            case 'Drum Master':
                return 9;
            case 'Bass Basic':
                return 11;
            case 'Bass Advanced':
                return 12;
            case 'Bass Extreme':
                return 13;
            case 'Bass Master':
                return 14;
            default:
                return null;
        }
    },

    render: function() {
        var chart = this.convertChart(this.state.chart);

        return (
            <div>
                <div className="section">
                    <div className="songname">{window.name}</div>
                    <div className="songartist">{window.artist}</div>
                    <div className="songdifficulty">{window.difficulties[chart]/100}</div>
                </div>
                <div className="section">
                    {valid_charts.map(function(chart) {
                        return (
                            <Nav
                                title={chart}
                                active={this.state.chart == chart}
                                onClick={function(event) {
                                    if (this.state.chart == chart) { return; }
                                    this.setState({chart: chart});
                                    pagenav.navigate(chart);
                                }.bind(this)}
                            />
                        );
                    }.bind(this))}
                </div>
                <div className="section">
               		<Table
                        className="list topscores"
                        columns={[
                            {
                                name: 'Name',
                                render: function(topscore) {
                                    return (
                                        <a href={Link.get('player', topscore.userid)}>{
                                            this.state.players[topscore.userid].name
                                        }</a>
                                    );
                                }.bind(this),
                                sort: function(a, b) {
                                    var an = this.state.players[a.userid].name;
                                    var bn = this.state.players[b.userid].name;
                                    return an.localeCompare(bn);
                                }.bind(this),
                            },
                            {
                                name: 'Skill',
                                render: function(topscore) { return topscore.points / 100; },
                                sort: function(a, b) {
                                    return (a.points - b.points) / 100;
                                },
                                reverse: true,
                            },
                            {
                                name: 'Combo',
                                render: function(topscore) { return topscore.combo > 0 ? topscore.combo : '-'; },
                            },
                            {
                                name: 'Music Rate',
                                render: function(topscore) { return topscore.perc == -1 ? '-' : topscore.perc / 100 + '%' ; },
                            },
                            {
                                name: 'Score',
                                render: function(topscore) { return topscore.stats.score},
                            },
                            {
                                name: 'Perfect',
                                render: function(topscore) { return topscore.stats.perfect},
                            },
                            {
                                name: 'Great',
                                render: function(topscore) { return topscore.stats.great},
                            },
                            {
                                name: 'Good',
                                render: function(topscore) { return topscore.stats.good},
                            },
                            {
                                name: 'Ok',
                                render: function(topscore) { return topscore.stats.ok},
                            },
                            {
                                name: 'Miss',
                                render: function(topscore) { return topscore.stats.miss},
                            },
                        ]}
                        defaultsort='Skill'
                        rows={this.state.topscores[chart]}
                        key={chart}
                        paginate={10}
                        emptymessage="There are no scores for this chart."
                    />
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(top_scores, null),
    document.getElementById('content')
);
