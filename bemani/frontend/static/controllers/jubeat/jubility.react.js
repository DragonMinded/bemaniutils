/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var jubility_view = createReactClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        return {
            player: window.player,
            songs: window.songs,
            profiles: profiles,
            version: pagenav.getInitialState(profiles[profiles.length - 1]),
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(version) {
            this.setState({version: version});
        }.bind(this));
        this.refreshProfile();
    },

    refreshProfile: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                var profiles = Object.keys(response.player);

                this.setState({
                    player: response.player,
                    profiles: profiles,
                });
                setTimeout(this.refreshProfile, 5000);
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

    renderJubilityBreakdown: function(player) {
        if (this.state.version == 13) // festo
            return (
                <div className='row'>
                    {this.renderFestoJubilityTable(player, true)}
                    {this.renderFestoJubilityTable(player, false)}
                </div>
            );
        if (this.state.version == 12) // clan
            return (
                <div className='row'>
                    {this.renderClanJubilityTable(player)}
                </div>
            );

        return null;
    },

    renderClanJubilityTable: function(player) {
        if (typeof player.chart === 'undefined' || player.chart.length == 0) {
            return null;
        }
        return(
            <div className='col-6 col-12-medium'>
                <p>
                    <b><b>Chart breakdown</b></b>
                </p>
                <p>Individual song jubility gets averaged to calculate player total jubility.</p>
                <Table
                    className='list jubility'
                    columns={[
                        {
                            name: 'Song',
                            render: function(entry) {
                                return (
                                    <a href={Link.get('individual_score', entry.songid, this.convertChart(entry.chart))}>
                                        <div>{ this.state.songs[entry.songid].name }</div>
                                    </a>
                                );
                            }.bind(this),
                        },
                        {
                            name: 'Hard Mode',
                            render: function(entry) { return entry.hard_mode ? 'Yes' : 'No'; }
                        },
                        {
                            name: 'Jubility',
                            render: function(entry) { return (entry.value / 100.0).toFixed(2); },
                            sort: function(a, b) {
                                return a.value - b.value;
                            },
                            reverse: true,
                        },
                    ]}
                    defaultsort='Jubility'
                    rows={player.chart}
                />
            </div>
        );
    },

    renderFestoJubilityTable: function(player, pickup) {
        if (pickup == true)
            jubilityChart = player.pick_up_chart;
        else
            jubilityChart = player.common_chart;
        if (typeof jubilityChart === 'undefined' || jubilityChart.length == 0) {
            return null;
        }
        return(
            <div className='col-6 col-12-medium'>
                <p>
                    <b>
                    {pickup == true ? <b>Pick up chart breakdown</b> : <b>Common chart breakdown</b>}
                    </b>
                </p>
                <p>Individual song jubility gets added to calculate total jubility.</p>
                <Table 
                    className='list jubility'
                    columns={[
                        {
                            name: 'Song',
                            render: function(entry) {
                                return (
                                    <a href={Link.get('individual_score', entry.music_id, this.convertChart(entry.seq))}>
                                        <div>{ this.state.songs[entry.music_id].name }</div>
                                    </a>
                                );
                            }.bind(this),
                        },
                        {
                            name: 'Hard Mode',
                            render: function(entry) { return entry.seq >= 3 ? 'Yes' : 'No'; }
                        },
                        {
                            name: 'Music Rate',
                            render: function(entry) { return entry.music_rate.toFixed(1) + '%'; },
                            sort: function(a, b) {
                                return a.music_rate - b.music_rate;
                            },
                            reverse: true,
                        },
                        {
                            name: 'Jubility',
                            render: function(entry) { return entry.value.toFixed(1); },
                            sort: function(a, b) {
                                return a.value - b.value;
                            },
                            reverse: true,
                        },
                    ]}
                    defaultsort='Jubility'
                    rows={jubilityChart}
                />
            </div>
        );
    },

    renderJubility: function(player) {
        return(
            // version == prop ( No Jubility )
            this.state.version == 10 ?
            <div>
                <p>This version of jubeat doesn't support Jubility</p>
            </div>
            :
            // version == qubell ( No Jubility )
            this.state.version == 11 ?
            <div>
                <p>This version of jubeat doesn't support Jubility</p>
            </div>
            :
            // version == festo
            this.state.version == 13 ? 
                <div>
                    <LabelledSection label='Jubility'>
                    {(player.common_jubility+player.pick_up_jubility).toFixed(1)}
                    </LabelledSection>
                    <LabelledSection label='Common Jubility'>
                        {player.common_jubility.toFixed(1)}
                    </LabelledSection>
                    <LabelledSection label='Pick up Jubility'>
                        {player.pick_up_jubility.toFixed(1)}
                    </LabelledSection>
                </div>
            :
            // Default which version >= Saucer except qubell and festo
            this.state.version >= 8 ? 
                <div>
                    <LabelledSection label='Jubility'>
                    {player.jubility / 100}
                    </LabelledSection>
                </div>
            :
            <div>
                <p>This version of jubeat doesn't support Jubility</p>
            </div>
        )
    },

    render: function() {
        if (this.state.player[this.state.version]) {
            var player = this.state.player[this.state.version];
            var item = Object.keys(window.versions).map(function(k){
                return window.versions[k]
            })
            return (
                <div>
                    <section>
                        <p>
                            <b>
                                <a href={Link.get('profile', null, this.state.version)}>&larr; Back To Profile</a>
                            </b>
                        </p>
                    </section>
                    <section>
                        <h3>{player.name}'s jubility</h3>
                        <p>
                            {this.state.profiles.map(function(version) {
                                if (version < 12) {
                                    // No breakdown here, no point in displaying.
                                    return null;
                                }
                                return (
                                    <Nav
                                        title={window.versions[version]}
                                        active={this.state.version == version}
                                        onClick={function(event) {
                                            if (this.state.version == version) { return; }
                                            this.setState({
                                                version: version,
                                            });
                                            pagenav.navigate(version);
                                        }.bind(this)}
                                    />
                                );
                            }.bind(this))}
                        </p>
                    </section>
                    <section>
                        {this.renderJubility(player)}
                    </section>
                    <section>
                        {this.renderJubilityBreakdown(player)}
                    </section>
                </div>
            );
        } else {
            var item = Object.keys(window.versions).map(function(k){
                return window.versions[k]
            })
            return (
                <div>
                    <section>
                        <p>
                            <SelectVersion
                                name='version'
                                value={ item.indexOf(item[this.state.version - 1]) }
                                versions={ item }
                                onChange={function(event) {
                                    var version = item.indexOf(item[event]) + 1
                                    if (this.state.version == version) { return; }
                                    this.setState({version: version});
                                    pagenav.navigate(version);
                                }.bind(this)}
                            />
                        </p>
                    </section>
                    <section>
                        <p>This player has no profile for {window.versions[this.state.version]}!</p>
                    </section>
                </div>
            );
        }
    },
});

ReactDOM.render(
    React.createElement(jubility_view, null),
    document.getElementById('content')
);
