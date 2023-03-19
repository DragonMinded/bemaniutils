/*** @jsx React.DOM */

function makeGameSettingName(game_settings) {
    return game_settings.game + '-' + game_settings.version;
}

var GameSettings = createReactClass({
    getInitialState: function() {
        var valid_settings = this.props.game_settings.map(function(setting) {
            return makeGameSettingName(setting);
        });
        var pagenav = new History(valid_settings);

        return {
            pagenav: pagenav,
            settings: this.props.game_settings,
            current_setting: pagenav.getInitialState(makeGameSettingName(this.props.game_settings[0])),
            settings_changed: {},
            settings_saving: {},
            settings_saved: {},
        };
    },

    componentDidMount: function() {
        this.state.pagenav.onChange(function(setting) {
            this.setState({current_setting: setting});
        }.bind(this));
    },

    getSettingIndex: function(setting_name) {
        var real_index = -1;
        this.state.settings.map(function(game_settings, index) {
            var current = makeGameSettingName(game_settings);
            if (current == setting_name) { real_index = index; }
        }.bind(this));
        return real_index;
    },

    setChanged: function(val) {
        this.state.settings_changed[this.state.current_setting] = val;
        return this.state.settings_changed;
    },

    setSaving: function(val) {
        this.state.settings_saving[this.state.current_setting] = val;
        return this.state.settings_saving;
    },

    setSaved: function(val) {
        this.state.settings_saved[this.state.current_setting] = val;
        return this.state.settings_saved;
    },

    saveSettings: function(event) {
        var index = this.getSettingIndex(this.state.current_setting);
        this.setState({settings_saving: this.setSaving(true), settings_saved: this.setSaved(false)});
        AJAX.post(
            Link.get('update_settings'),
            this.state.settings[index],
            function(response) {
                this.state.settings[index] = response.game_settings;
                this.setState({
                    settings: this.state.settings,
                    settings_saving: this.setSaving(false),
                    settings_saved: this.setSaved(true),
                    settings_changed: this.setChanged(false),
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    render: function() {
        return (
            <div>
                <div className="section settings-nav">
                    { this.state.settings.map(function(game_settings) {
                        var current = makeGameSettingName(game_settings);
                        return (
                            <Nav
                                title={game_settings.name}
                                active={this.state.current_setting == current}
                                showAlert={this.state.settings_changed[current]}
                                onClick={function(event) {
                                    if (this.state.current_setting == current) { return; }
                                    this.setState({current_setting: current});
                                    this.state.pagenav.navigate(current);
                                }.bind(this)}
                            />
                        );
                    }.bind(this))}
                </div>
                <div className="section">
                    { this.state.settings[this.getSettingIndex(this.state.current_setting)].ints.map(function(setting, index) {
                        return (
                            <div className="arcade menuoption">
                                <Tip
                                    text={setting.tip}
                                >
                                    <label htmlFor={setting.setting}>{setting.name}:</label>
                                    <SelectInt
                                        name={setting.setting}
                                        id={setting.setting}
                                        value={setting.value}
                                        choices={setting.values}
                                        onChange={function(value) {
                                            this.state.settings[this.getSettingIndex(this.state.current_setting)].ints[index].value = value;
                                            this.setState({
                                                settings: this.state.settings,
                                                settings_changed: this.setChanged(true),
                                            });
                                        }.bind(this)}
                                    />
                                </Tip>
                            </div>
                        );
                    }.bind(this))}
                    { this.state.settings[this.getSettingIndex(this.state.current_setting)].bools.map(function(setting, index) {
                        return (
                            <div className="arcade menuoption">
                                <Tip
                                    text={setting.tip}
                                >
                                    <label htmlFor={setting.setting}>{setting.name}:</label>
                                    <input
                                        name={setting.setting}
                                        id={setting.setting}
                                        type="checkbox"
                                        checked={setting.value}
                                        onChange={function(event) {
                                            this.state.settings[this.getSettingIndex(this.state.current_setting)].bools[index].value = event.target.checked;
                                            this.setState({
                                                settings: this.state.settings,
                                                settings_changed: this.setChanged(true),
                                            });
                                        }.bind(this)}
                                    />
                                </Tip>
                            </div>
                        );
                    }.bind(this))}
                    { this.state.settings[this.getSettingIndex(this.state.current_setting)].strs.map(function(setting, index) {
                        return (
                            <div className="arcade menuoption">
                                <Tip
                                    text={setting.tip}
                                >
                                    <label htmlFor={setting.setting}>{setting.name}:</label>
                                    <input
                                        name={setting.setting}
                                        id={setting.setting}
                                        type="text"
                                        value={setting.value}
                                        onChange={function(event) {
                                            this.state.settings[this.getSettingIndex(this.state.current_setting)].strs[index].value = event.target.value;
                                            this.setState({
                                                settings: this.state.settings,
                                                settings_changed: this.setChanged(true),
                                            });
                                        }.bind(this)}
                                    />
                                </Tip>
                            </div>
                        );
                    }.bind(this))}
                    { this.state.settings[this.getSettingIndex(this.state.current_setting)].longstrs.map(function(setting, index) {
                        return (
                            <div className="arcade menuoption">
                                <Tip
                                    text={setting.tip}
                                >
                                    <label htmlFor={setting.setting}>{setting.name}:</label>
                                    <textarea
                                        name={setting.setting}
                                        id={setting.setting}
                                        value={setting.value}
                                        onChange={function(event) {
                                            this.state.settings[this.getSettingIndex(this.state.current_setting)].longstrs[index].value = event.target.value;
                                            this.setState({
                                                settings: this.state.settings,
                                                settings_changed: this.setChanged(true),
                                            });
                                        }.bind(this)}
                                    />
                                </Tip>
                            </div>
                        );
                    }.bind(this))}
                    <input
                        type="submit"
                        disabled={!this.state.settings_changed[this.state.current_setting]}
                        value="save"
                        onClick={function(event) {
                            this.saveSettings(event);
                        }.bind(this)}
                    />
                    { this.state.settings_saving[this.state.current_setting] ?
                        <img className="loading" src={Link.get('static', window.assets + 'loading-16.gif')} /> :
                        null
                    }
                    { this.state.settings_saved[this.state.current_setting] ?
                        <span>{ "\u2713" }</span> :
                        null
                    }
                </div>
            </div>
        );
    },
});
