/*** @jsx React.DOM */

var network_scores = createReactClass({
    getInitialState: function(props) {
        return {
            songs: window.songs,
            attempts: window.attempts,
            players: window.players,
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
            case 1:
                return 'Gituar Basic';
            case 2:
                return 'Gituar Advanced';
            case 3:
                return 'Gituar Extreme';
            case 4:
                return 'Gituar Master';
            case 6:
                return 'Drum Basic';
            case 7:
                return 'Drum Advanced';
            case 8:
                return 'Drum Extreme';
            case 9:
                return 'Drum Master';
            case 11:
                return 'Bass Basic';
            case 12:
                return 'Bass Advanced';
            case 13:
                return 'Bass Extreme';
            case 14:
                return 'Bass Master';
            default:
                return 'u broke it';
        }
    },

    convertChartLink: function(chart) {
        switch(chart) {
            case 1:
                return 'Gituar Basic';
            case 2:
                return 'Gituar Advanced';
            case 3:
                return 'Gituar Extreme';
            case 4:
                return 'Gituar Master';
            case 6:
                return 'Drum Basic';
            case 7:
                return 'Drum Advanced';
            case 8:
                return 'Drum Extreme';
            case 9:
                return 'Drum Master';
            case 11:
                return 'Bass Basic';
            case 12:
                return 'Bass Advanced';
            case 13:
                return 'Bass Extreme';
            case 14:
                return 'Bass Master';
            default:
                return 'nothing';
        }
    },

    renderScore: function(score) {
        return (
            <div className="score">
                <div>
                    <span className="label">Skills</span>
                    <span className="score">{score.points / 100}</span>
                    <span className="bolder">Music Rate:</span> {score.perc == -1 ? '-' : score.perc / 100 +'%'}
                <div>
                </div>
                    <span className="status">Score level:</span> {score.status}
                    <br/>
                    <span className="bolder">Stats:</span>
                    {score.stats.score}
                    <span> / </span>
                    {score.stats.perfect}
                    <span> / </span>
                    {score.stats.great}
                    <span> / </span>
                    {score.stats.good}
                    <span> / </span>
                    {score.stats.ok}
                    <span> / </span>
                    {score.stats.miss}
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
                            <th>Song</th>
                            <th>Chart</th>
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
                                            <a href={Link.get('individual_score', attempt.songid, this.convertChartLink(attempt.chart))}>{
                                                this.convertChart(attempt.chart)
                                            }</a>
                                        </div>
                                        <div>{
                                            this.state.songs[attempt.songid].difficulties[attempt.chart]/100
                                        }</div>
                                    </td>
                                    <td>{ this.renderScore(attempt) }</td>
                                </tr>
                            );
                        }.bind(this))}
                    </tbody>
                    <tfoot>
                        <tr>
                            <td colSpan={5}>
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
