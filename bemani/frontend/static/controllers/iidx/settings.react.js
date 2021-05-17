/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var menu_option_names = {
    'alphabet': 'alphabet folders',
    'classic_hispeed': 'classic hispeed',
    'difficulty': 'difficulty folders',
    'disable_graph_cutin': 'disable graph cut-in',
    'disable_hcn_color': 'disable hcn color',
    'disable_song_preview': 'disable song previews',
    'effector_lock': 'lock effector',
    'grade': 'grade folders',
    'hide_iidx_id': 'hide iidx id',
    'hide_play_count': 'hide play count on profile',
    'rival_info': 'rival info box',
    'rival_played': 'rival played folders',
    'rival_win_lose': 'rival win/lose folders',
    'status': 'status folders',
};
var valid_menu_options = [
    'grade',
    'status',
    'difficulty',
    'alphabet',
    'rival_played',
    'rival_win_lose',
    'rival_info',
    'hide_play_count',
    'disable_graph_cutin',
    'classic_hispeed',
    'hide_iidx_id',
    'disable_song_preview',
    'effector_lock',
    'disable_hcn_color',
];
var theme_option_names = {
    'beam': 'Note Beam',
    'bgm': 'Menu BGM',
    'burst': 'Note Burst',
    'frame': 'Frame',
    'full_combo': 'Full Combo Effect',
    'judge': 'Judge Font',
    'noteskin': 'Note Skin',
    'towel': 'Lane Cover',
    'turntable': 'Turntable Decal',
    'voice': 'Menu Announcer Voice',
    'pacemaker': 'Pacemaker Skin',
    'effector_preset': 'Effector Preset',
    'explosion_size': 'Explosion Size',
    'note_preview': 'Note Preview',
};
var valid_qpro_options = [
    'body',
    'face',
    'hair',
    'hand',
    'head',
];

var settings_view = React.createClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        var version = pagenav.getInitialState(profiles[profiles.length - 1]);
        return {
            player: window.player,
            profiles: profiles,
            version: version,
            menu_changed: {},
            theme_changed: {},
            qpro_changed: {},
            menu_saving: {},
            theme_saving: {},
            qpro_saving: {},
            menu_saved: {},
            theme_saved: {},
            qpro_saved: {},
            new_name: window.player[version].name,
            editing_name: false,
            new_prefecture: window.player[version].prefecture,
            editing_prefecture: false,
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(version) {
            this.setState({version: version});
        }.bind(this));
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    setQproChanged: function(val) {
        this.state.qpro_changed[this.state.version] = val;
        return this.state.qpro_changed
    },

    setQproSaving: function(val) {
        this.state.qpro_saving[this.state.version] = val;
        return this.state.qpro_saving;
    },

    setQproSaved: function(val) {
        this.state.qpro_saved[this.state.version] = val;
        return this.state.qpro_saved;
    },

    setMenuChanged: function(val) {
        this.state.menu_changed[this.state.version] = val;
        return this.state.menu_changed;
    },

    setMenuSaving: function(val) {
        this.state.menu_saving[this.state.version] = val;
        return this.state.menu_saving;
    },

    setMenuSaved: function(val) {
        this.state.menu_saved[this.state.version] = val;
        return this.state.menu_saved;
    },

    setThemeChanged: function(val) {
        this.state.theme_changed[this.state.version] = val;
        return this.state.theme_changed;
    },

    setThemeSaving: function(val) {
        this.state.theme_saving[this.state.version] = val;
        return this.state.theme_saving;
    },

    setThemeSaved: function(val) {
        this.state.theme_saved[this.state.version] = val;
        return this.state.theme_saved;
    },

    saveQproOptions: function(event) {
        this.setState({qpro_saving: this.setQproSaving(true), qpro_saved: this.setQproSaved(false)});
        AJAX.post(
            Link.get('updateqpro'),
            {
                version: this.state.version,
                qpro: this.state.player[this.state.version].qpro,
            },
            function(response) {
                var player = this.state.player
                player[response.version].qpro = response.qpro;
                this.setState({
                    player: player,
                    qpro_saving: this.setQproSaving(false),
                    qpro_saved: this.setQproSaved(true),
                    qpro_changed: this.setQproChanged(false),
                })
            }.bind(this)
        )
    },

    saveMenuOptions: function(event) {
        this.setState({menu_saving: this.setMenuSaving(true), menu_saved: this.setMenuSaved(false)});
        AJAX.post(
            Link.get('updateflags'),
            {
                version: this.state.version,
                flags: this.state.player[this.state.version].flags,
            },
            function(response) {
                var player = this.state.player;
                player[response.version].flags = response.flags;
                this.setState({
                    player: player,
                    menu_saving: this.setMenuSaving(false),
                    menu_saved: this.setMenuSaved(true),
                    menu_changed: this.setMenuChanged(false),
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveThemeOptions: function(event) {
        this.setState({theme_saving: this.setThemeSaving(true), theme_saved: this.setThemeSaved(false)});
        AJAX.post(
            Link.get('updatesettings'),
            {
                version: this.state.version,
                settings: this.state.player[this.state.version].settings,
            },
            function(response) {
                var player = this.state.player;
                player[response.version].settings = response.settings;
                this.setState({
                    player: player,
                    theme_saving: this.setThemeSaving(false),
                    theme_saved: this.setThemeSaved(true),
                    theme_changed: this.setThemeChanged(false),
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveDJName: function(event) {
        AJAX.post(
            Link.get('updatename'),
            {
                version: this.state.version,
                name: this.state.new_name,
            },
            function(response) {
                var player = this.state.player;
                player[response.version].name = response.name;
                this.setState({
                    player: player,
                    new_name: this.state.player[response.version].name,
                    editing_name: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    savePrefecture: function(event) {
        AJAX.post(
            Link.get('updateprefecture'),
            {
                version: this.state.version,
                prefecture: this.state.new_prefecture,
            },
            function(response) {
                var player = this.state.player;
                player[response.version].prefecture = response.prefecture;
                this.setState({
                    player: player,
                    new_prefecture: this.state.player[response.version].prefecture,
                    editing_prefecture: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    leaveArcade: function(event) {
        AJAX.post(
            Link.get('leavearcade'),
            {
                version: this.state.version,
            },
            function(response) {
                var player = this.state.player;
                player[response.version].arcade = "";
                this.setState({
                    player: player,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    renderDJName: function(player) {
        return (
            <LabelledSection vertical={true} label="DJ Name">{
                !this.state.editing_name ?
                    <span>
                        <span>{player.name}</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_name: true});
                            }.bind(this)}
                        />
                    </span> :
                    <form className="inline" onSubmit={this.saveDJName}>
                        <input
                            type="text"
                            className="inline"
                            maxlength="6"
                            size="6"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_name}
                            onChange={function(event) {
                                var value = event.target.value.toUpperCase();
                                var intRegex = /^[-&$#\\.\\?\\*!A-Z0-9]*$/;
                                if (value.length <= 6 && intRegex.test(value)) {
                                    this.setState({new_name: value});
                                }
                            }.bind(this)}
                            name="name"
                        />
                        <input
                            type="submit"
                            value="save"
                        />
                        <input
                            type="button"
                            value="cancel"
                            onClick={function(event) {
                                this.setState({
                                    new_name: this.state.player[this.state.version].name,
                                    editing_name: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    renderPrefecture: function(player) {
        regions = this.state.version >= 25 ? Regions2 : Regions;
        return (
            <LabelledSection vertical={true} label="Prefecture">{
                !this.state.editing_prefecture ?
                    <span>
                        <span>{regions[player.prefecture]}</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_prefecture: true});
                            }.bind(this)}
                        />
                    </span> :
                    <form className="inline" onSubmit={this.savePrefecture}>
                        <SelectInt
                            name="prefecture"
                            value={this.state.new_prefecture}
                            choices={regions}
                            onChange={function(choice) {
                                this.setState({new_prefecture: choice});
                            }.bind(this)}
                        />
                        <input
                            type="submit"
                            value="save"
                        />
                        <input
                            type="button"
                            value="cancel"
                            onClick={function(event) {
                                this.setState({
                                    new_prefecture: this.state.player[this.state.version].prefecture,
                                    editing_prefecture: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    renderHomeArcade: function(player) {
        if (!player.arcade || player.arcade == "") {
            return (
                <LabelledSection vertical={true} label="Home Arcade">
                    <span className="placeholder">no arcade</span>
                </LabelledSection>
            );
        }

        return (
            <LabelledSection vertical={true} label="Home Arcade">
                <span>{player.arcade}</span>
                <Delete
                    title='leave arcade'
                    onClick={function(event) {
                        this.leaveArcade(event);
                    }.bind(this)}
                />
            </LabelledSection>
        );
    },

    render: function() {
        if (this.state.player[this.state.version]) {
            var player = this.state.player[this.state.version];
            return (
                <div>
                    <div className="section">
                        {this.state.profiles.map(function(version) {
                            return (
                                <Nav
                                    title={window.versions[version]}
                                    active={this.state.version == version}
                                    showAlert={this.state.menu_changed[version] || this.state.theme_changed[version]}
                                    onClick={function(event) {
                                        if (this.state.editing_name || this.state.editing_prefecture) { return; }
                                        if (this.state.version == version) { return; }
                                        this.setState({
                                            version: version,
                                            new_name: this.state.player[version].name,
                                            new_prefecture: this.state.player[version].prefecture,
                                        });
                                        pagenav.navigate(version);
                                    }.bind(this)}
                                />
                            );
                        }.bind(this))}
                    </div>
                    <div className="section">
                        <h3>User Profile</h3>
                        {this.renderDJName(player)}
                        {this.renderPrefecture(player)}
                        {this.renderHomeArcade(player)}
                    </div>
                    <div className="section">
                        <h3>QPro</h3>
                        <form className="inline">
                            <div className="fields">
                                {
                                    valid_qpro_options.map(function(qpro_option) {
                                        var player = this.state.player[this.state.version]
                                        var items = window.qpros[this.state.version].filter(function (qpro) {                                                
                                            return qpro.type == qpro_option
                                        });
                                        var results = {};
                                        items
                                            .map(function(item) { return { 'id': item.id, 'name': `${item.name}` } })
                                            .forEach (value => results[value.id] = value.name);
                                        return (
                                            <div className="field">
                                            <b>{qpro_option}</b>
                                            <br/>
                                            <SelectInt
                                                name={qpro_option}
                                                value={player.qpro[qpro_option]}
                                                choices={results}
                                                onChange={function(choice) {
                                                    var player = this.state.player;
                                                    player[this.state.version].qpro[qpro_option] = choice;
                                                    this.setState({
                                                        player: player,
                                                        qpro_changed: this.setQproChanged(true),
                                                    })
                                                }.bind(this)}
                                            />
                                        </div>
                                        )
                                    }.bind(this))
                                }
                                <div className="field">
                                    <input
                                        type="submit"
                                        value="save"
                                        disabled={!this.state.qpro_changed[this.state.version]}
                                        onClick={function(event) {
                                            this.saveQproOptions(event);
                                        }.bind(this)}
                                    />
                                    { this.state.qpro_saving[this.state.version] ?
                                        <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                                        null
                                    }
                                    { this.state.qpro_saved[this.state.version] ?
                                        <span>&#x2713;</span> :
                                        null
                                    }
                                </div>
                            </div>
                        </form>
                    </div>
                    <div className="section">
                        <h3>Theme</h3>
                        {Object.keys(IIDXOptions[this.state.version]).map(function(theme_option) {
                            return (
                                <LabelledSection
                                    className="iidx themeoption"
                                    vertical={true}
                                    label={theme_option_names[theme_option]}
                                >
                                    <SelectInt
                                        name={theme_option}
                                        value={player.settings[theme_option]}
                                        choices={IIDXOptions[this.state.version][theme_option]}
                                        onChange={function(choice) {
                                            var player = this.state.player;
                                            player[this.state.version].settings[theme_option] = choice;
                                            this.setState({
                                                player: player,
                                                theme_changed: this.setThemeChanged(true),
                                            });
                                        }.bind(this)}
                                    />
                                </LabelledSection>
                            );
                        }.bind(this))}
                        <input
                            type="submit"
                            value="save"
                            disabled={!this.state.theme_changed[this.state.version]}
                            onClick={function(event) {
                                this.saveThemeOptions(event);
                            }.bind(this)}
                        />
                        { this.state.theme_saving[this.state.version] ?
                            <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                            null
                        }
                        { this.state.theme_saved[this.state.version] ?
                            <span>{ "\u2713" }</span> :
                            null
                        }
                    </div>
                    <div className="section">
                        <h3>Menu Options</h3>
                        {valid_menu_options.map(function(menu_option) {
                            return (
                                <div className="iidx menuoption">
                                    <input
                                        name={menu_option}
                                        id={menu_option}
                                        type="checkbox"
                                        checked={player.flags[menu_option]}
                                        onChange={function(event) {
                                            var player = this.state.player;
                                            player[this.state.version].flags[menu_option] = event.target.checked;
                                            this.setState({
                                                player: player,
                                                menu_changed: this.setMenuChanged(true),
                                            });
                                        }.bind(this)}
                                    />
                                    <label htmlFor={menu_option}>{menu_option_names[menu_option]}</label>
                                </div>
                            );
                        }.bind(this))}
                        <input
                            type="submit"
                            disabled={!this.state.menu_changed[this.state.version]}
                            value="save"
                            onClick={function(event) {
                                this.saveMenuOptions(event);
                            }.bind(this)}
                        />
                        { this.state.menu_saving[this.state.version] ?
                            <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                            null
                        }
                        { this.state.menu_saved[this.state.version] ?
                            <span>{ "\u2713" }</span> :
                            null
                        }
                    </div>
                </div>
            );
        } else {
            return (
                <div>
                    <div className="section">
                        You have no profile for {window.versions[this.state.version]}!
                    </div>
                    <div className="section">
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
                    </div>
                </div>
            );
        }
    },
});

ReactDOM.render(
    React.createElement(settings_view, null),
    document.getElementById('content')
);
