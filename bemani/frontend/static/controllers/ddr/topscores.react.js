/*** @jsx React.DOM */

var chart_map = [0, 1, 2, 3, 4, 6, 7, 8, 9];
var valid_charts = ['SP Beginner', 'SP Basic', 'SP Difficult', 'SP Expert', 'SP Challenge', 'DP Basic', 'DP Difficult', 'DP Expert', 'DP Challenge'].filter(function(val, index) {
    return window.difficulties[window.chart_map[index]] > 0;
});
var pagenav = new History(valid_charts);

var top_scores = createReactClass({

    sortTopScores: function(topscores) {
        var newscores = [[], [], [], [], [], [], [], [], [], []];
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
            case 'SP Beginner':
                return 0;
            case 'SP Basic':
                return 1;
            case 'SP Difficult':
                return 2;
            case 'SP Expert':
                return 3;
            case 'SP Challenge':
                return 4;
            case 'DP Basic':
                return 5;
            case 'DP Difficult':
                return 6;
            case 'DP Expert':
                return 7;
            case 'DP Challenge':
                return 8;
            default:
                return null;
        }
    },

    getGroove: function(chart) {
        return [
            500 + window.groove[chart].stream * 11,
            500 + window.groove[chart].chaos * 0.5,
            500 + window.groove[chart].freeze * 1,
            500 + window.groove[chart].air * 64,
            500 + window.groove[chart].voltage * 4.5,
        ];
    },

    render: function() {
        var chart = this.convertChart(this.state.chart);
        if (
            window.groove[window.chart_map[chart]].stream != 0 ||
            window.groove[window.chart_map[chart]].chaos != 0 ||
            window.groove[window.chart_map[chart]].freeze != 0 ||
            window.groove[window.chart_map[chart]].air != 0 ||
            window.groove[window.chart_map[chart]].voltage != 0
        ) {
            var hasGroove = true;
        } else {
            var hasGroove = false;
        }

        return (
            <div>
                <div className="section">
                    { hasGroove ? <div className="floating right">
                        <RadarGraph
                            data={{
                                labels: ['Stream', 'Chaos', 'Freeze', 'Air', 'Voltage'],
                                datasets: [{
                                    data: this.getGroove(window.chart_map[chart]),
                                    fill: true,
                                    backgroundColor: "rgba(54, 162, 235, 0.2)",
                                    borderColor: "rgb(54, 162, 235)",
                                }],
                            }}
                            options={{
                                scale: {
                                    ticks: {
                                        callback: function(tick, index, ticks) {
                                            return '';
                                        },
                                        min: 0,
                                        max: 4000,
                                        beginAtZero: true,
                                        stepSize: 4000,
                                    },
                                },
                                elements: {
                                    point: {
                                        radius: 0,
                                    },
                                },
                                legend: {
                                    display: false,
                                },
                                tooltips: {
                                    enabled: false,
                                },
                                animation: false,
                                responsive: false,
                            }}
                            width="250"
                            height="200"
                        />
                    </div> : null }
                    <div className="left">
                        <div className="songname">{window.name}</div>
                        <div className="songartist">{window.artist}</div>
                        <div className="songdifficulty">{window.difficulties[window.chart_map[chart]]}</div>
                    </div>
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
                                name: 'Grade',
                                render: function(topscore) { return <span className="grade">{topscore.rank}</span>; },
                            },
                            {
                                name: 'Score',
                                render: function(topscore) { return topscore.points; },
                                sort: function(a, b) {
                                    return a.points - b.points;
                                },
                                reverse: true,
                            },
                            {
                                name: 'Combo',
                                sort: function(a, b) {
                                    return a.combo - b.combo;
                                },
                                reverse: true,
                                render: function(topscore) { return topscore.combo >= 0 ? topscore.combo : '-'; },
                            },
                            {
                                name: 'Halo',
                                render: function(topscore) { return topscore.halo; },
                            },
                        ]}
                        defaultsort='Score'
                        rows={this.state.topscores[window.chart_map[chart]]}
                        key={window.chart_map[chart]}
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
