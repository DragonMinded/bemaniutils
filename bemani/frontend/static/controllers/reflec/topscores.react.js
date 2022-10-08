/*** @jsx React.DOM */

var valid_charts = ['Basic', 'Medium', 'Hard', 'Special'].filter(function(val, index) {
    return window.difficulties[index] > 0;
});
var pagenav = new History(valid_charts);

var top_scores = createReactClass({

    sortTopScores: function(topscores) {
        var newscores = [[], [], [], [], []];
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
            case 'Medium':
                return 1;
            case 'Hard':
                return 2;
            case 'Special':
                return 3;
            default:
                return null;
        }
    },

    renderGrade: function(score) {
        if (score.achievement_rate < 6000) {
            return <span>C</span>;
        }
        if (score.achievement_rate < 7000) {
            return <span>B</span>;
        }
        if (score.achievement_rate < 8000) {
            return <span>A</span>;
        }
        if (score.achievement_rate < 9000) {
            return <span>AA</span>;
        }
        if (score.achievement_rate < 9500) {
            return <span>AAA</span>;
        }

        return <span>AAA+</span>;
    },

    render: function() {
        var chart = this.convertChart(this.state.chart);

        return (
            <div>
                <div className="section">
                    <div className="songname">{window.name}</div>
                    <div className="songartist">{window.artist}</div>
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
                                name: 'Achievement Rate',
                                render: function(topscore) {
                                    return (
                                        <div className="score">
                                            <span className="grade">{this.renderGrade(topscore)}</span>
                                            <span className="percent">{topscore.achievement_rate/100}%</span>
                                        </div>
                                    );
                                }.bind(this),
                                sort: function(a, b) {
                                    return a.achievement_rate - b.achievement_rate;
                                },
                            },
                            {
                                name: 'Clear Type',
                                render: function(topscore) { return topscore.combo_type + ' ' + topscore.clear_type; },
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
                                name: 'Miss Count',
                                render: function(topscore) { return topscore.miss_count >= 0 ? topscore.miss_count : '-'; },
                                sort: function(a, b) {
                                    return a.miss_count - b.miss_count;
                                },
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
