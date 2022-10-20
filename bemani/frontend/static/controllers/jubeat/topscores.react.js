/*** @jsx React.DOM */

var valid_charts = window.new_rating ?
    ['Basic', 'Advanced', 'Extreme', 'Hard Mode Basic', 'Hard Mode Advanced', 'Hard Mode Extreme'] :
    ['Basic', 'Advanced', 'Extreme'];
var pagenav = new History(valid_charts);

var top_scores = createReactClass({

    sortTopScores: function(topscores) {
        var newscores = [[], [], [], [], [], []];
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
            case 'Basic':
                return 0;
            case 'Advanced':
                return 1;
            case 'Extreme':
                return 2;
            case 'Hard Mode Basic':
                return 3;
            case 'Hard Mode Advanced':
                return 4;
            case 'Hard Mode Extreme':
                return 5;
            default:
                return null;
        }
    },

    render: function() {
        var chart = this.convertChart(this.state.chart);
        var diff = window.difficulties[chart];

        return (
            <div>
                <div className="section">
                    <div className="songname">{window.name}</div>
                    <div className="songartist">{window.artist}</div>
                    <div className="songdifficulty">{diff >= 9 && window.new_rating ? diff.toFixed(1) : diff.toFixed(0)}★</div>
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
                                name: 'Music Rate',
                                render: function(topscore) { return topscore.music_rate >= 0 ? topscore.music_rate + "%" : '-'; },
                                sort: function(a, b) {
                                    return a.music_rate - b.music_rate;
                                },
                                reverse: true,
                            },
                            {
                                name: 'Judgement Stats',
                                render: function(topscore) {
                                    has_stats = (
                                        topscore.stats.perfect > 0 ||
                                        topscore.stats.great > 0 ||
                                        topscore.stats.good > 0 ||
                                        topscore.stats.poor > 0 ||
                                        topscore.stats.miss > 0
                                    );
                                    return has_stats ? <div title="perfect / great / good / poor / miss">
                                        {topscore.stats.perfect}
                                        <span> / </span>
                                        {topscore.stats.great}
                                        <span> / </span>
                                        {topscore.stats.good}
                                        <span> / </span>
                                        {topscore.stats.poor}
                                        <span> / </span>
                                        {topscore.stats.miss}
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
