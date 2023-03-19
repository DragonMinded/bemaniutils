/*** @jsx React.DOM */

var network_scores = createReactClass({
    getInitialState: function(props) {
        return {
            songs: window.songs,
            attempts: window.attempts,
            players: window.players,
            versions: window.versions,
            loading: true,
            offset: 0,
            limit: 10,
        };
    },

    componentDidMount: function() {
        this.refreshScores();
    },

    refreshScores: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    attempts: response.attempts,
                    players: response.players,
                    loading: false,
                });
                // Refresh every 15 seconds
                setTimeout(this.refreshScores, 15000);
            }.bind(this)
        );
    },

    convertChart: function(chart) {
        switch(chart) {
            case 0:
                return 'SPN';
            case 1:
                return 'SPH';
            case 2:
                return 'SPA';
            case 3:
                return 'DPN';
            case 4:
                return 'DPH';
            case 5:
                return 'DPA';
            case 6:
                return 'BEGINNER';
            default:
                return 'u broke it';
        }
    },

    renderScore: function(score) {
        var topscore = window.songs[score.songid].notecounts[score.chart] * 2;
        var percent = score.points / topscore;
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

        return (
            <div className="score">
                {topscore > 0 ?
                    <div>
                        <span className="grade">{grades[grade]}</span>
                        <span className="percent">{(percent * 100).toFixed(2)}%</span>
                    </div> :
                    null
                }
                <div>
                    <span className="label">EX</span>
                    <span className="score">{score.points}</span>
                    <span className="label">M</span>
                    <span className="score">{score.miss_count < 0 ? '-' : score.miss_count}</span>
                </div>
                <div>
                    <span className="status">{score.status}</span>
                </div>
            </div>
        );
    },

    render: function() {
        return (
            <div>
                <table className="list attempts">
                    <thead>
                        <tr>
                            { window.showdjnames ? <th>DJ Name</th> : null }
                            { window.showdjnames ? <th>Arcade</th> : null }
                            <th>Timestamp</th>
                            <th>Song / Artist</th>
                            <th>Difficulty</th>
                            <th>Score</th>
                        </tr>
                    </thead>
                    <tbody>
                        {this.state.attempts.map(function(attempt, index) {
                            if (index < this.state.offset || index >= this.state.offset + this.state.limit) {
                                return null;
                            }

                            return (
                                <tr>
                                    { window.showdjnames ? <td><a href={Link.get('player', attempt.userid)}>{
                                        this.state.players[attempt.userid].name
                                    }</a></td> : null }
                                    { window.showdjnames ? <td>{ this.state.players[attempt.userid].arcade }</td> : null }
                                    <td>
                                        <div>
                                            <Timestamp timestamp={attempt.timestamp} />
                                            { window.shownewrecords && attempt.raised ?
                                                <span className="raised">new high score!</span> :
                                                null
                                            }
                                        </div>
                                    </td>
                                    <td className="center">
                                        <a href={Link.get('individual_score', attempt.songid)}>
                                            <div className="songname">{ this.state.songs[attempt.songid].name }</div>
                                            <div className="songartist">{ this.state.songs[attempt.songid].artist }</div>
                                            <div className="songgenre">{ this.state.songs[attempt.songid].genre }</div>
                                        </a>
                                    </td>
                                    <td className="center">
                                        <div>
                                            {attempt.chart == 6 ?
                                                this.convertChart(attempt.chart) :
                                                <a href={Link.get('individual_score', attempt.songid, this.convertChart(attempt.chart))}>{
                                                     this.convertChart(attempt.chart)
                                                }</a>
                                            }
                                        </div>
                                        <div>{attempt.chart == 6 ?
                                            null :
                                            <span>{window.songs[attempt.songid].difficulties[attempt.chart]}★</span>
                                        }</div>
                                    </td>
                                    <td>{ this.renderScore(attempt) }</td>
                                </tr>
                            );
                        }.bind(this))}
                    </tbody>
                    <tfoot>
                        <tr>
                            <td colSpan={6}>
                                { this.state.offset > 0 ?
                                    <Prev onClick={function(event) {
                                         var page = this.state.offset - this.state.limit;
                                         if (page < 0) { page = 0; }
                                         this.setState({offset: page});
                                    }.bind(this)}/> : null
                                }
                                { (this.state.offset + this.state.limit) < this.state.attempts.length ?
                                    <Next style={ {float: 'right'} } onClick={function(event) {
                                         var page = this.state.offset + this.state.limit;
                                         if (page >= this.state.attempts.length) { return }
                                         this.setState({offset: page});
                                    }.bind(this)}/> :
                                    this.state.loading ?
                                        <span className="loading" style={ {float: 'right' } }>
                                            <img
                                                className="loading"
                                                src={Link.get('static', window.assets + 'loading-16.gif')}
                                            /> loading more scores...
                                        </span> : null
                                }
                            </td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(network_scores, null),
    document.getElementById('content')
);
