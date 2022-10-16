/*** @jsx React.DOM */

var possible_events = [
    'unhandled_packet',
    'exception',
    'unauthorized_pcbid',
    'jubeat_league_course',
    'jubeat_fc_challenge_charts',
    'jubeat_random_course_charts',
    'iidx_daily_charts',
    'pcbevent',
    'paseli_transaction',
    'pnm_course',
    'ddr_profile_purge',
];

var event_names = {
    'unhandled_packet': 'Unhandled Packets',
    'exception': 'Exceptions',
    'unauthorized_pcbid': 'Unauthorized PCBIDs',
    'jubeat_league_course': 'Jubeat League Courses',
    'jubeat_fc_challenge_charts': 'Jubeat Full Combo Challenge Charts',
    'jubeat_random_course_charts': 'Jubeat Random 10s Course Charts',
    'iidx_daily_charts': 'IIDX Daily Charts',
    'pnm_course': 'Pop\'n Music Course',
    'pcbevent': 'PCB Events',
    'paseli_transaction': 'PASELI Transactions',
    'ddr_profile_purge': 'DDR Ace Profile Purge',
};

var mergehandler = new MergeManager(function(evt) { return evt.id; }, MergeManager.MERGE_POLICY_DROP);

var audit_events = createReactClass({
    getInitialState: function(props) {
        return {
            events: mergehandler.add(window.events),
            users: window.users,
            arcades: window.arcades,
            iidxsongs: window.iidxsongs,
            jubeatsongs: window.jubeatsongs,
            pnmsongs: window.pnmsongs,
            iidxversions: window.iidxversions,
            jubeatversions: window.jubeatversions,
            pnmversions: window.pnmversions,
            filtering: window.possible_events,
            offset: 0,
            limit: 10,
        };
    },

    componentDidMount: function() {
        this.loadOldEvents();
        this.refreshEvents();
    },

    loadOldEvents: function() {
        // If there's no events on the network, don't try loading old ones
        if (this.state.events.length == 0) { return; }

        var min_id = this.state.events.reduce(function(a, b) {
            return a < b.id ? a : b.id;
        }, this.state.events[0].id);
        AJAX.get(
            Link.get('backfill', min_id),
            function(response) {
                this.setState({
                    events: mergehandler.add(response.events),
                });
                // Keep loading until we grab all events
                if (response.events.length > 0) {
                    setTimeout(this.loadOldEvents, 1);
                }
            }.bind(this)
        );
    },

    refreshEvents: function() {
        var max_id = this.state.events.reduce(function(a, b) {
            if (!a) { return b.id; }
            return a > b.id ? a : b.id;
        }, 0);
        AJAX.get(
            Link.get('refresh', max_id),
            function(response) {
                this.setState({
                    events: mergehandler.add(response.events),
                    users: response.users,
                    arcades: response.arcades,
                });
                // Refresh every 15 seconds
                setTimeout(this.refreshEvents, 5000);
            }.bind(this)
        );
    },

    getEvents: function() {
        return this.state.events.filter(function(event) {
            return this.state.filtering.indexOf(event.type) >= 0;
        }.bind(this));
    },

    renderFilters: function() {
        return (
            <div className="section">
                {window.possible_events.map(function(event_id) {
                    return (
                        <span className="filter">
                            <input
                                name={event_id}
                                id={event_id}
                                type="checkbox"
                                checked={this.state.filtering.indexOf(event_id) >= 0}
                                onChange={function(event) {
                                    var filtering = this.state.filtering;
                                    if (event.target.checked) {
                                        filtering.push(event_id);
                                    } else {
                                        filtering = filtering.filter(function(f) {
                                            return f != event_id;
                                        }.bind(this));
                                    }
                                    this.setState({filtering: filtering, offset: 0});
                                }.bind(this)}
                            />
                            <label htmlFor={event_id}>{window.event_names[event_id]}</label>
                        </span>
                    );
                }.bind(this))}
            </div>
        );
    },

    render: function() {
        var events = this.getEvents().sort(function(a, b) {
            return b.id - a.id;
        });
        if (events.length == 0) {
            return (
                <div>
                    {this.renderFilters()}
                    <div className="section">
                        <span className="placeholder">No events to display!</span>
                    </div>
                </div>
            );
        }
        return (
            <div>
                {this.renderFilters()}
                <div className="section">
                    <table className="list events">
                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Event</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {events.map(function(event, index) {
                                if (index < this.state.offset || index >= this.state.offset + this.state.limit) {
                                    return null;
                                }

                                if (event.type == 'unhandled_packet') {
                                    return <UnhandledPacketEvent event={event} />;
                                } else if(event.type == 'exception') {
                                    return <ExceptionEvent event={event} />;
                                } else if(event.type == 'unauthorized_pcbid') {
                                    return <UnauthorizedClientEvent event={event} />;
                                } else if(event.type == 'jubeat_league_course') {
                                    return <JubeatLeagueCourseEvent event={event} versions={this.state.jubeatversions} songs={this.state.jubeatsongs} />;
                                } else if(event.type == 'jubeat_fc_challenge_charts') {
                                    return <JubeatFCChallengeEvent event={event} versions={this.state.jubeatversions} songs={this.state.jubeatsongs} />;
                                } else if(event.type == 'jubeat_random_course_charts') {
                                    return <JubeatRandomCourseEvent event={event} versions={this.state.jubeatversions} songs={this.state.jubeatsongs} />;
                                } else if(event.type == 'iidx_daily_charts') {
                                    return <IIDXDailyChartsEvent event={event} versions={this.state.iidxversions} songs={this.state.iidxsongs} />;
                                } else if(event.type == 'pcbevent') {
                                    return <PCBEvent event={event} />;
                                } else if(event.type == 'paseli_transaction') {
                                    return <PASELITransactionEvent event={event} users={this.state.users} arcades={this.state.arcades} />;
                                } else if(event.type == 'pnm_course') {
                                    return <PopnMusicCourseEvent event={event} versions={this.state.pnmversions} songs={this.state.pnmsongs} />;
                                } else if(event.type == 'ddr_profile_purge') {
                                    return <DDRProfilePurge event={event} users={this.state.users} />;
                                } else {
                                    return <UnknownEvent event={event} />;
                                }
                            }.bind(this))}
                        </tbody>
                        <tfoot>
                            <tr>
                                <td colSpan={3}>
                                    { this.state.offset > 0 ?
                                        <Prev onClick={function(event) {
                                             var page = this.state.offset - this.state.limit;
                                             if (page < 0) { page = 0; }
                                             this.setState({offset: page});
                                        }.bind(this)}/> : null
                                    }
                                    { (this.state.offset + this.state.limit) < events.length ?
                                        <Next style={ {float: 'right'} } onClick={function(event) {
                                             var page = this.state.offset + this.state.limit;
                                             if (page >= events.length) { return }
                                             this.setState({offset: page});
                                        }.bind(this)}/> : null
                                    }
                                </td>
                            </tr>
                        </tfoot>
                    </table>
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(audit_events, null),
    document.getElementById('content')
);
