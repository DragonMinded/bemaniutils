/*** @jsx React.DOM */

var valid_charts = ['SPN', 'SPH', 'SPA', 'DPN', 'DPH', 'DPA'].filter(function(val, index) {
    return window.difficulties[index] > 0;
});
var pagenav = new History(valid_charts);

var top_scores = createReactClass({

    sortTopScores: function(topscores) {
        var newscores = [[], [], [], [], [], []];
        topscores.map(function(score) {
            newscores[score.chart].push(score);
        }.bind(this));
        return newscores;
    },

    getInitialViewingState: function(topscores, chart) {
        var index = this.convertChart(chart);
        if (topscores[index].length > 0) {
            var hash = null;
            var maxpoints = 0;
            topscores[index].map(function(topscore) {
                if (topscore.points > maxpoints) {
                    hash = this.hashScore(topscore);
                    maxpoints = topscore.points;
                }
            }.bind(this));
            return [hash, null, null, null, null];
        } else {
            return [null, null, null, null, null];
        }
    },

    hashScore: function(topscore) {
        if (topscore.ghost) {
            return topscore.songid + '-' + topscore.chart + '-' + topscore.ghost.join(',');
        } else {
            return topscore.songid + '-' + topscore.chart;
        }
    },

    getInitialState: function(props) {
        var topscores = this.sortTopScores(window.topscores);
        var chart = pagenav.getInitialState(valid_charts[0]);
        var viewing = this.getInitialViewingState(topscores, chart);
        return {
            topscores: topscores,
            players: window.players,
            chart: chart,
            viewing: viewing,
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(chart) {
            var viewing = this.getInitialViewingState(this.state.topscores, chart);
            this.setState({chart: chart, viewing: viewing});
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
            case 'SPN':
                return 0;
            case 'SPH':
                return 1;
            case 'SPA':
                return 2;
            case 'DPN':
                return 3;
            case 'DPH':
                return 4;
            case 'DPA':
                return 5
            default:
                return null;
        }
    },

    renderGrade: function(chart, topscore) {
        var maxscore = window.notecounts[chart] * 2;
        var percent = topscore.points / maxscore;
        var grade = parseInt(9.0 * percent);
        var grades = [
            "F",
            "F",
            "E",
            "D",
            "C",
            "B",
            "A",
            "AA",
            "AAA",
            "MAX",
        ];

        var hash = this.hashScore(topscore);
        var index = this.state.viewing.indexOf(hash);
        var style = {};
        if (index >= 0) {
            style.color = this.getGhostColors()[index];
        }

        return (
            <div className="score">
                <Checkbox
                    checked={index >= 0}
                    onClick={function(event) {
                        if (index >= 0) {
                            // Remove it if it exists
                            var viewing = this.state.viewing;
                            viewing[index] = null;
                            this.setState({viewing: viewing});
                        } else {
                            // Add it if it doesn't exist and there's room
                            var addindex = this.state.viewing.indexOf(null);
                            if (addindex >= 0) {
                                var viewing = this.state.viewing;
                                viewing[addindex] = hash;
                                this.setState({viewing: viewing});
                            }
                        }
                    }.bind(this)}
                />
                <span style={style}>
                    <span className="grade">{grades[grade]}</span>
                    <span className="percent">{(percent * 100).toFixed(2)}%</span>
                </span>
            </div>
        );
    },

    calculateGhost: function(ghost) {
        var total = 0;
        var ghost = ghost.map(function(val) {
            var out = val + total;
            total = total + val;
            return out;
        });
        ghost.unshift(0);
        return ghost;
    },

    getGhostColors: function() {
        return [
            'rgba(255,99,132,1)',
            'rgba(255,153,0,1)',
            'rgba(153,204,0,1)',
            'rgba(0,204,255,1)',
            'rgba(153,51,255,1)',
        ];
    },

    render: function() {
        var chart = this.convertChart(this.state.chart);

        // Handle rendering the chart, finding any non-null viewing indexes
        var ghosts = Array(this.state.viewing.length).fill(null);
        var colors = this.getGhostColors();
        var notecounts = null;
        var aaa = null;
        var aa = null;
        var a = null;
        var zero = null;

        this.state.topscores[chart].map(function(topscore) {
            var index = this.state.viewing.indexOf(this.hashScore(topscore));
            if (index >= 0) {
                ghosts[index] = this.calculateGhost(topscore.ghost);
            }
        }.bind(this));

        // Filter out to preserve colors at the time of selection
        colors = colors.filter(function(color, index) {
            return ghosts[index] != null;
        });
        ghosts = ghosts.filter(function(ghost) {
            return ghost != null;
        });
        if (ghosts.length > 0) {
            notecounts = window.notecounts[chart] * 2
            aaa = Array(ghosts[0].length).fill(notecounts * (8/9));
            aa = Array(ghosts[0].length).fill(notecounts * (7/9));
            a = Array(ghosts[0].length).fill(notecounts * (6/9));
            zero = Array(ghosts[0].length).fill(0);
        }

        return (
            <div>
                <div className="section">
                    <div className="floating right">{ ghosts.length > 0 ?
                        <div className="section">
                            <LineGraph
                                data={{
                                    labels: zero,
                                    datasets: ghosts.map(function(ghost, index) {
                                        return {
                                            fill: false,
                                            data: ghost,
                                            borderColor: [
                                                colors[index],
                                            ],
                                            borderWidth: 2,
                                        };
                                    }.bind(this)).concat([
                                        {
                                            fill: false,
                                            data: aaa,
                                            borderColor: [
                                                'rgba(0,0,0,0.25)',
                                            ],
                                            borderWidth: 1,
                                        },
                                        {
                                            fill: false,
                                            data: aa,
                                            borderColor: [
                                                'rgba(0,0,0,0.25)',
                                            ],
                                            borderWidth: 1,
                                        },
                                        {
                                            fill: false,
                                            data: a,
                                            borderColor: [
                                                'rgba(0,0,0,0.25)',
                                            ],
                                            borderWidth: 1,
                                        },
                                        {
                                            fill: false,
                                            data: zero,
                                            borderColor: [
                                                'rgba(0,0,0,0.25)',
                                            ],
                                            borderWidth: 1,
                                        },
                                    ]),
                                }}
                                options={{
                                    scales: {
                                        xAxes: [{
                                            display: false,
                                        }],
                                        yAxes: [{
                                            grid: {
                                                display: false,
                                            },
                                            gridLines: {
                                                display: false,
                                            },
                                            ticks: {
                                                callback: function(tick, index, ticks) {
                                                    switch(index) {
                                                        case 0:
                                                            return 'MAX';
                                                        case 1:
                                                            return 'AAA';
                                                        case 2:
                                                            return 'AA';
                                                        case 3:
                                                            return 'A';
                                                        default:
                                                            return '';
                                                    }
                                                },
                                                beginAtZero:true,
                                                min: 0,
                                                max: notecounts,
                                                stepSize: notecounts / 9,
                                            }
                                        }],
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
                                    responsive: false,
                                    animation: false,
                                }}
                                width="320"
                                height="200"
                            />
                        </div> : <div style={{width: '320px', height: '200px'}}></div>
                    }</div>
                    <div className="left">
                        <div className="songname">{window.name}</div>
                        <div className="songartist">{window.artist}</div>
                        <div className="songgenre">{window.genre}</div>
                        <div className="songdifficulty">{window.difficulties[chart]}★</div>
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
                                    var viewing = this.getInitialViewingState(this.state.topscores, chart);
                                    this.setState({chart: chart, viewing: viewing});
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
                                name: 'DJ Name',
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
                                name: 'Arcade',
                                render: function(topscore) { return this.state.players[topscore.userid].arcade; }.bind(this),
                            },
                            {
                                name: 'Status',
                                render: function(topscore) { return topscore.status; },
                            },
                            {
                                name: 'Grade',
                                render: function(topscore) { return this.renderGrade(chart, topscore); }.bind(this),
                            },
                            {
                                name: 'EX Score',
                                render: function(topscore) { return topscore.points; },
                                sort: function(a, b) {
                                    return a.points - b.points;
                                },
                                reverse: true,
                            },
                            {
                                name: 'Miss Count',
                                render: function(topscore) { return topscore.miss_count; },
                                sort: function(a, b) {
                                    return a.miss_count - b.miss_count;
                                },
                            },
                        ]}
                        defaultsort='EX Score'
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
