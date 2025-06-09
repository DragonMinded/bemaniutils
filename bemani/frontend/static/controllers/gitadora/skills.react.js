/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var skills_view = createReactClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        return {
            player: window.player,
            songs: window.songs,
            profiles: profiles,
            version: pagenav.getInitialState(profiles[profiles.length - 1]),
        };
    },

    renderSkillsGF: function(player) {
        return (
            this.state.version >= 7 ? 
                <div>
                    <LabelledSection label="GF Skills">{player.gf_skills / 100}</LabelledSection>
                    <LabelledSection label="GF All Skills">{player.gf_all_skills / 100}</LabelledSection>
                    <LabelledSection label="GF Classic Skills">{player.gf_classic_all_skills / 100}</LabelledSection>
                    <LabelledSection label="GF Clear">{player.gf_clear_music_num}</LabelledSection>
                    <LabelledSection label="GF FC">{player.gf_full_music_num}</LabelledSection>
                    <LabelledSection label="GF EXFC">{player.gf_exce_music_num}</LabelledSection>
                    <LabelledSection label="GF Highest Clear">{player.gf_clear_diff / 100}</LabelledSection>
                    <LabelledSection label="GF Highest FC">{player.gf_full_diff / 100}</LabelledSection>
                    <LabelledSection label="GF Highest EXFC">{player.gf_exce_diff / 100}</LabelledSection>
                </div>
            :
            <div>
                <p>This version of Gitadora doesn't support Skills</p>
            </div>
        )
    },

    renderSkillsDM: function(player) {
        return (
            this.state.version >= 7 ? 
                <div>
                    <LabelledSection label="DM Skills">{player.dm_skills / 100}</LabelledSection>
                    <LabelledSection label="DM All Skills">{player.dm_all_skills / 100}</LabelledSection>
                    <LabelledSection label="DM Classic Skills">{player.dm_classic_all_skills / 100}</LabelledSection>
                    <LabelledSection label="DM Clear">{player.dm_clear_music_num}</LabelledSection>
                    <LabelledSection label="DM FC">{player.dm_full_music_num}</LabelledSection>
                    <LabelledSection label="DM EXFC">{player.dm_exce_music_num}</LabelledSection>
                    <LabelledSection label="DM Highest Clear">{player.dm_clear_diff / 100}</LabelledSection>
                    <LabelledSection label="DM Highest FC">{player.dm_full_diff / 100}</LabelledSection>
                    <LabelledSection label="DM Highest EXFC">{player.dm_exce_diff / 100}</LabelledSection>
                </div>
            :
            <div>
                <p>This version of Gitadora doesn't support Skills</p>
            </div>
        )
    },

    renderSkillTableGF: function(player) {
        if (this.state.version >= 7)
            return (
                <div className='row'>
                    {this.renderSkillTableGFHot(player)}
                    {this.renderSkillTableGFOther(player)}
                </div>
            );
        return null;
    },

    renderSkillTableDM: function(player) {
        if (this.state.version >= 7)
            return (
                <div className='row'>
                    {this.renderSkillTableDMHot(player)}
                    {this.renderSkillTableDMOther(player)}
                </div>
            );
        return null;
    },

    renderSkillTableGFHot: function(player) { 
        if (typeof player.gf_exist === 'undefined' || player.gf_exist.length == 0) {
            return null;
        }
        return(
            this.state.version >= 7 ? 
                <div className='col-6 col-12-medium'>
                    <p>
                        <b>
                            <b>Guitarfreaks HOT</b>
                        </b>
                    </p>
                    <Table 
                        className='list guitarfreaks'
                        columns={[
                            {
                                name: 'Music',
                                render: function(entry) {return entry.music_name},
                            },
                            {
                                name: 'Difficulty',
                                render: function(entry) {return entry.chart},
                            },
                            {
                                name: 'Level',
                                render: function(entry) {return entry.music_difficulties / 100},
                            },
                            {
                                name: 'Skill',
                                render: function(entry) { return entry.skills_point / 100; },
                                    sort: function(a, b) {
                                        return (a.skills_point - b.skills_point) / 100
                                    },
                                    reverse: true,
                            },
                            {
                                name: 'Perc',
                                render: function(entry) { return entry.perc == -1 ? '-' : entry.perc / 100 + '%' ; },
                            },
                        ]}
                        defaultsort='Skill'
                        rows={player.gf_exist}
                    />
                </div>
            :
            <div>
                <p>This version of Gitadora doesn't support Skills</p>
            </div>
        );
    },

    renderSkillTableGFOther: function(player) { 
        if (typeof player.gf_new === 'undefined' || player.gf_new.length == 0) {
            return null;
        }
        return(
            this.state.version >= 7 ? 
                <div className='col-6 col-12-medium'>
                    <p>
                        <b>
                            <b>Guitarfreaks Other</b>
                        </b>
                    </p>
                    <Table 
                        className='list guitarfreaks'
                        columns={[
                            {
                                name: 'Music',
                                render: function(entry) {return entry.music_name},
                            },
                            {
                                name: 'Difficulty',
                                render: function(entry) {return entry.chart},
                            },
                            {
                                name: 'Level',
                                render: function(entry) {return entry.music_difficulties / 100},
                            },
                            {
                                name: 'Skill',
                                render: function(entry) { return entry.skills_point / 100; },
                                    sort: function(a, b) {
                                        return (a.skills_point - b.skills_point) / 100
                                    },
                                    reverse: true,
                            },
                            {
                                name: 'Perc',
                                render: function(entry) { return entry.perc == -1 ? '-' : entry.perc / 100 + '%' ; },
                            },
                        ]}
                        defaultsort='Skill'
                        rows={player.gf_new}
                    />
                </div>
            :
            <div>
                <p>This version of Gitadora doesn't support Skills</p>
            </div>
        );
    },

    renderSkillTableDMHot: function(player) { 
        if (typeof player.dm_exist === 'undefined' || player.dm_exist.length == 0) {
            return null;
        }
        return(
            this.state.version >= 7 ? 
                <div className='col-6 col-12-medium'>
                    <p>
                        <b>
                            <b>Drummania HOT</b>
                        </b>
                    </p>
                    <Table 
                        className='list drummania'
                        columns={[
                            {
                                name: 'Music',
                                render: function(entry) {return entry.music_name},
                            },
                            {
                                name: 'Difficulty',
                                render: function(entry) {return entry.chart},
                            },
                            {
                                name: 'Level',
                                render: function(entry) {return entry.music_difficulties / 100},
                            },
                            {
                                name: 'Skill',
                                render: function(entry) { return entry.skills_point / 100; },
                                    sort: function(a, b) {
                                        return (a.skills_point - b.skills_point) / 100
                                    },
                                    reverse: true,
                            },
                            {
                                name: 'Perc',
                                render: function(entry) { return entry.perc == -1 ? '-' : entry.perc / 100 + '%' ; },
                            },
                        ]}
                        defaultsort='Skill'
                        rows={player.dm_exist}
                    />
                </div>
            :
            <div>
                <p>This version of Gitadora doesn't support Skills</p>
            </div>
        );
    },

    renderSkillTableDMOther: function(player) { 
        if (typeof player.dm_new === 'undefined' || player.dm_new.length == 0) {
            return null;
        }
        return(
            this.state.version >= 7 ? 
                <div className='col-6 col-12-medium'>
                    <p>
                        <b>
                            <b>Drummania Other</b>
                        </b>
                    </p>
                    <Table 
                        className='list drummania'
                        columns={[
                            {
                                name: 'Music',
                                render: function(entry) {return entry.music_name},
                            },
                            {
                                name: 'Difficulty',
                                render: function(entry) {return entry.chart},
                            },
                            {
                                name: 'Level',
                                render: function(entry) {return entry.music_difficulties / 100},
                            },
                            {
                                name: 'Skill',
                                render: function(entry) { return entry.skills_point / 100; },
                                    sort: function(a, b) {
                                        return (a.skills_point - b.skills_point) / 100
                                    },
                                    reverse: true,
                            },
                            {
                                name: 'Perc',
                                render: function(entry) { return entry.perc == -1 ? '-' : entry.perc / 100 + '%' ; },
                            },
                        ]}
                        defaultsort='Skill'
                        rows={player.dm_new}
                    />
                </div>
            :
            <div>
                <p>This version of Gitadora doesn't support Skills</p>
            </div>
        );
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
                        <h3>{player.name}'s Skills</h3>
                        <p>
                            {this.state.profiles.map(function(version) {
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
                    <div>
                        <section>
                            {this.renderSkillsGF(player)}
                        </section>
                        <section>
                            {this.renderSkillTableGF(player)}
                        </section>
                    </div>
                    <div>
                        <section>
                            {this.renderSkillsDM(player)}
                        </section>
                        <section>
                            {this.renderSkillTableDM(player)}
                        </section>
                    </div>
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
    }
});

ReactDOM.render(
    React.createElement(skills_view, null),
    document.getElementById('content')
);