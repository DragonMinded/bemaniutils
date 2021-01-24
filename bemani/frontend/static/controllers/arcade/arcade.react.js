/*** @jsx React.DOM */

function makeSettingName(game_settings) {
    return game_settings.game + '-' + game_settings.version;
}
var valid_settings = window.game_settings.map(function(setting) {
    return makeSettingName(setting);
});
var pagenav = new History(valid_settings);

var arcade_management = React.createClass({
    getInitialState: function(props) {
        var credits = {};
        Object.keys(window.users).map(function(userid) {
            credits[userid] = '';
        });
        return {
            id: window.arcade.id,
            name: window.arcade.name,
            description: window.arcade.description,
            paseli_enabled: window.arcade.paseli_enabled,
            paseli_infinite: window.arcade.paseli_infinite,
            mask_services_url: window.arcade.mask_services_url,
            pin: window.arcade.pin,
            editing_pin: false,
            new_pin: '',
            paseli_enabled_saving: false,
            paseli_infinite_saving: false,
            mask_services_url_saving: false,
            machines: window.machines,
            settings: window.game_settings,
            current_setting: pagenav.getInitialState(makeSettingName(window.game_settings[0])),
            settings_changed: {},
            settings_saving: {},
            settings_saved: {},
            users: window.users,
            balances: window.balances,
            credits: credits,
            events: window.events,
            eventoffset: 0,
            eventlimit: 5,
            credit_card: '',
            credit_amount: '',
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(setting) {
            this.setState({current_setting: setting});
        }.bind(this));
        this.refreshArcade();
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    refreshArcade: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    users: response.users,
                    balances: response.balances,
                    machines: response.machines,
                    events: response.events,
                });
                // Refresh every 15 seconds
                setTimeout(this.refreshArcade, 5000);
            }.bind(this)
        );
    },

    savePin: function(event) {
        AJAX.post(
            Link.get('update_pin'),
            {pin: this.state.new_pin},
            function(response) {
                this.setState({
                    pin: response.pin,
                    new_pin: '',
                    editing_pin: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    getSettingIndex: function(setting_name) {
        var real_index = -1;
        this.state.settings.map(function(game_settings, index) {
            var current = makeSettingName(game_settings);
            if (current == setting_name) { real_index = index; }
        }.bind(this));
        return real_index;
    },

    togglePaseliEnabled: function(event) {
        this.setState({paseli_enabled_saving: true})
        AJAX.post(
            Link.get('paseli_enabled'),
            {value: !this.state.paseli_enabled},
            function(response) {
                this.setState({
                    paseli_enabled: response.value,
                    paseli_enabled_saving: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    togglePaseliInfinite: function(event) {
        this.setState({paseli_infinite_saving: true})
        AJAX.post(
            Link.get('paseli_infinite'),
            {value: !this.state.paseli_infinite},
            function(response) {
                this.setState({
                    paseli_infinite: response.value,
                    paseli_infinite_saving: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    toggleMaskServicesURL: function(event) {
        this.setState({mask_services_url_saving: true})
        AJAX.post(
            Link.get('mask_services_url'),
            {value: !this.state.mask_services_url},
            function(response) {
                this.setState({
                    mask_services_url: response.value,
                    mask_services_url_saving: false,
                });
            }.bind(this)
        );
        event.preventDefault();
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

    addBalance: function(event) {
        var intval = parseInt(this.state.credit_amount);
        if (isNaN(intval)) {
            intval = 0;
        }
        AJAX.post(
            Link.get('add_balance'),
            {
                credits: intval,
                card: this.state.credit_card,
            },
            function(response) {
                var credits = {};
                Object.keys(response.users).map(function(userid) {
                    credits[userid] = '';
                });
                console.log('huh?');
                this.setState({
                    users: response.users,
                    balances: response.balances,
                    credits: credits,
                    events: response.events,
                    credit_card: '',
                    credit_amount: '',
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    updateBalance: function(event) {
        var updates = {};
        Object.keys(this.state.credits).map(function(userid) {
            var intval = parseInt(this.state.credits[userid]);
            if (!isNaN(intval)) {
                updates[userid] = intval;
            }
        }.bind(this));
        AJAX.post(
            Link.get('update_balance'),
            {credits: updates},
            function(response) {
                var credits = {};
                Object.keys(response.users).map(function(userid) {
                    credits[userid] = '';
                });
                this.setState({
                    users: response.users,
                    balances: response.balances,
                    credits: credits,
                    events: response.events,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    renderPIN: function() {
        return (
            <LabelledSection vertical={true} label="PIN">{
                !this.state.editing_pin ?
                    <span>
                        <span>{this.state.pin}</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_pin: true, new_pin: this.state.pin});
                            }.bind(this)}
                        />
                    </span> :
                    <form className="inline" onSubmit={this.savePin}>
                        <input
                            type="text"
                            className="inline"
                            maxlength="8"
                            size="8"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_pin}
                            onChange={function(event) {
                                var intRegex = /^\d*$/;
                                if (event.target.value.length <= 8 && intRegex.test(event.target.value)) {
                                    this.setState({new_pin: event.target.value});
                                }
                            }.bind(this)}
                            name="pin"
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
                                    new_pin: '',
                                    editing_pin: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    <LabelledSection vertical={true} label="Name">{ this.state.name }</LabelledSection>
                    <LabelledSection vertical={true} label="Description">{
                        this.state.description ?
                            <span>{ this.state.description }</span> :
                            <span className="placeholder">no description</span>
                    }</LabelledSection>
                    {this.renderPIN()}
                    <LabelledSection vertical={true} label="PASELI Enabled">
                        <span>{ this.state.paseli_enabled ? 'yes' : 'no' }</span>
                        <Toggle onClick={this.togglePaseliEnabled.bind(this)} />
                        { this.state.paseli_enabled_saving ?
                            <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                            null
                        }
                    </LabelledSection>
                    <LabelledSection vertical={true} label="PASELI Infinite">
                        <span>{ this.state.paseli_infinite ? 'yes' : 'no' }</span>
                        <Toggle onClick={this.togglePaseliInfinite.bind(this)} />
                        { this.state.paseli_infinite_saving ?
                            <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                            null
                        }
                    </LabelledSection>
                    <LabelledSection vertical={true} label="Mask Web Address">
                        <span>{ this.state.mask_services_url ? 'yes' : 'no' }</span>
                        <Toggle onClick={this.toggleMaskServicesURL.bind(this)} />
                        { this.state.mask_services_url_saving ?
                            <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                            null
                        }
                    </LabelledSection>
                </div>
                <div className="section">
                    <h3>PCBIDs Assigned to This Arcade</h3>
                    <Table
                        className="list machine"
                        columns={[
                            {
                                name: "PCBID",
                                render: function(machine) { return machine.pcbid; },
                                sort: function(a, b) { return a.pcbid.localeCompare(b.pcbid); },
                            },
                            {
                                name: "Name",
                                render: function(machine) { return machine.name; },
                                sort: function(a, b) { return a.name.localeCompare(b.name); },
                            },
                            {
                                name: "Description",
                                render: function(machine) { return machine.description; },
                                sort: function(a, b) { return a.description.localeCompare(b.description); },
                            },
                            {
                                name: "Applicable Game",
                                render: function(machine) { return machine.game; },
                                sort: function(a, b) { return a.game.localeCompare(b.game); },
                                hidden: !window.enforcing,
                            },
                            {
                                name: "Port",
                                render: function(machine) { return machine.port; },
                                sort: function(a, b) { return a.port - b.port; },
                            },
                        ]}
                        rows={this.state.machines}
                        emptymessage="There are no PCBIDs assigned to this arcade."
                    />
                </div>
                <div className="section settings-nav">
                    <h3>Game Settings For This Arcade</h3>
                    { this.state.settings.map(function(game_settings) {
                        var current = makeSettingName(game_settings);
                        return (
                            <Nav
                                title={game_settings.name}
                                active={this.state.current_setting == current}
                                showAlert={this.state.settings_changed[current]}
                                onClick={function(event) {
                                    if (this.state.current_setting == current) { return; }
                                    this.setState({current_setting: current});
                                    pagenav.navigate(current);
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
                        <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                            null
                    }
                    { this.state.settings_saved[this.state.current_setting] ?
                        <span>{ "\u2713" }</span> :
                            null
                    }
                </div>
                <div className="section">
                    <h3>User PASELI Balances for This Arcade</h3>
                    { Object.keys(this.state.balances).length == 0 ?
                        <div>
                            <span className="placeholder">No users with balances for this arcade!</span>
                        </div> :
                        <form onSubmit={this.updateBalance}>
                            <table className="list blance">
                                <thead>
                                    <tr>
                                        <th>User</th>
                                        <th>Current Balance</th>
                                        <th>Credit Amount</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {Object.keys(this.state.balances).map(function(userid) {
                                        var user = this.state.users[userid];
                                        return (
                                            <tr>
                                                <td>{ user ?
                                                    <span>{user}</span> :
                                                    <span className="placeholder">anonymous account</span>
                                                }</td>
                                                <td>{this.state.balances[userid]}</td>
                                                <td>
                                                    <input
                                                        type="text"
                                                        className="inline"
                                                        value={this.state.credits[userid]}
                                                        onChange={function(event) {
                                                            var credits = this.state.credits;
                                                            credits[userid] = event.target.value;
                                                            this.setState({credits: credits});
                                                        }.bind(this)}
                                                        name="credits"
                                                    />
                                                </td>
                                            </tr>
                                        );
                                    }.bind(this))}
                                </tbody>
                            </table>
                            <div className="action">
                                <input type="submit" value="update balance" />
                            </div>
                        </form>
                    }
                </div>
                <div className="section">
                    <h3>Credit PASELI via Card</h3>
                    <form onSubmit={this.addBalance}>
                        <table className="add blance">
                            <thead>
                                <tr>
                                    <th>Card Number</th>
                                    <th>Credit Amount</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>
                                        <input
                                            type="text"
                                            className="inline"
                                            value={this.state.credit_card}
                                            onChange={function(event) {
                                                this.setState({credit_card: event.target.value});
                                            }.bind(this)}
                                            name="card"
                                        />
                                    </td>
                                    <td>
                                        <input
                                            type="text"
                                            className="inline"
                                            value={this.state.credit_amount}
                                            onChange={function(event) {
                                                this.setState({credit_amount: event.target.value});
                                            }.bind(this)}
                                            name="credits"
                                        />
                                    </td>
                                    <td>
                                        <input type="submit" value="update balance" />
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </form>
                </div>
                <div className="section">
                    <h3>PASELI Transaction History</h3>
                    { this.state.events.length == 0 ?
                        <div>
                            <span className="placeholder">No events to display!</span>
                        </div> :
                        <table className="list events">
                            <thead>
                                <tr>
                                    <th>Timestamp</th>
                                    <th>Event</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {this.state.events.map(function(event, index) {
                                    if (index < this.state.eventoffset || index >= this.state.eventoffset + this.state.eventlimit) {
                                        return null;
                                    }

                                    if(event.type == 'paseli_transaction') {
                                        return <PASELITransactionEvent event={event} users={this.state.users} />;
                                    } else {
                                        return null;
                                    }
                                }.bind(this))}
                            </tbody>
                            <tfoot>
                                <tr>
                                    <td colSpan={3}>
                                        { this.state.eventoffset > 0 ?
                                            <Prev onClick={function(event) {
                                                 var page = this.state.eventoffset - this.state.eventlimit;
                                                 if (page < 0) { page = 0; }
                                                 this.setState({eventoffset: page});
                                            }.bind(this)}/> : null
                                        }
                                        { (this.state.eventoffset + this.state.eventlimit) < this.state.events.length ?
                                            <Next style={ {float: 'right'} } onClick={function(event) {
                                                 var page = this.state.eventoffset + this.state.eventlimit;
                                                 if (page >= this.state.events.length) { return }
                                                 this.setState({eventoffset: page});
                                            }.bind(this)}/> : null
                                        }
                                    </td>
                                </tr>
                            </tfoot>
                        </table>
                    }
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(arcade_management, null),
    document.getElementById('content')
);
