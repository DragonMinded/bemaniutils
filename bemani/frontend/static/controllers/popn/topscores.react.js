/*** @jsx React.DOM */

var valid_charts = ['Easy', 'Normal', 'Hyper', 'EX'].filter(function(val, index) {
    return window.difficulties[index] > 0;
});
var pagenav = new History(valid_charts);

var top_scores = createReactClass({

    sortTopScores: function(topscores) {
        var newscores = [[], [], [], []];
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
            case 'Easy':
                return 0;
            case 'Normal':
                return 1;
            case 'Hyper':
                return 2;
            case 'EX':
                return 3;
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
                    <div className="songgenre">{window.genre}</div>
                    <div className="songdifficulty">{window.difficulties[chart]}</div>
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
                                name: 'Status',
                                render: function(topscore) { return topscore.status; },
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
                                render: function(topscore) { return topscore.combo >= 0 ? topscore.combo : '-'; },
                                sort: function(a, b) {
                                    return a.combo - b.combo;
                                },
                                reverse: true,
                            },
                            {
                                name: 'Judgement Stats',
                                render: function(topscore) {
                                    has_stats = (
                                        topscore.stats.cool > 0 ||
                                        topscore.stats.great > 0 ||
                                        topscore.stats.good > 0 ||
                                        topscore.stats.bad > 0
                                    );
                                    return has_stats ? <div title="cool / great / good / bad">
                                        {topscore.stats.cool}
                                        <span> / </span>
                                        {topscore.stats.great}
                                        <span> / </span>
                                        {topscore.stats.good}
                                        <span> / </span>
                                        {topscore.stats.bad}
                                    </div> : null;
                                }
                            },
                        ]}
                        defaultsort='Score'
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
