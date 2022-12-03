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
                return 'Basic';
            case 1:
                return 'Advanced';
            case 2:
                return 'Extreme';
            case 3:
                return 'Hard Mode Basic';
            case 4:
                return 'Hard Mode Advanced';
            case 5:
                return 'Hard Mode Extreme';
            default:
                return 'u broke it';
        }
    },

    renderScore: function(score) {
        has_stats = (
            score.stats.perfect > 0 ||
            score.stats.great > 0 ||
            score.stats.good > 0 ||
            score.stats.poor > 0 ||
            score.stats.miss > 0
        );
        return (
            <div className="score">
                <div>
                    <span className="label">Score</span>
                    <span className="score">{score.points}</span>
                    <span className="label">Combo</span>
                    <span className="score">{score.combo < 0 ? '-' : score.combo}</span>
                    {score.music_rate >= 0 ? <>
                        <span className="label">Music Rate</span>
                        <span className="score">{score.music_rate <= 0 ? '-' : score.music_rate}%</span>
                    </> : null}
                </div>
                {has_stats ? <div title="perfect / great / good / poor / miss">
                    {score.stats.perfect}
                    <span> / </span>
                    {score.stats.great}
                    <span> / </span>
                    {score.stats.good}
                    <span> / </span>
                    {score.stats.poor}
                    <span> / </span>
                    {score.stats.miss}
                </div> : null}
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
                            { window.shownames ? <th>Name</th> : null }
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

                            var diff = window.songs[attempt.songid].difficulties[attempt.chart];
                            var new_rating = (
                                window.songs[attempt.songid].difficulties[3] > 0 ||
                                window.songs[attempt.songid].difficulties[4] > 0 ||
                                window.songs[attempt.songid].difficulties[5] > 0
                            );
                            return (
                                <tr>
                                    { window.shownames ? <td><a href={Link.get('player', attempt.userid)}>{
                                        this.state.players[attempt.userid].name
                                    }</a></td> : null }
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
                                        </a>
                                    </td>
                                    <td className="center">
                                        <div>
                                            <a href={Link.get('individual_score', attempt.songid, this.convertChart(attempt.chart))}>{
                                                this.convertChart(attempt.chart)
                                            }</a>
                                        </div>
                                        <div>
                                            <span>{diff >= 9 && new_rating ? diff.toFixed(1) : diff.toFixed(0)}★</span>
                                        </div>
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
