/*** @jsx React.DOM */

function count_pcbids(machines) {
    var count = 0;
    machines.map(function(machine) {
        count += (machine.editable ? 1 : 0);
    });
    return count;
}

var arcade_management = createReactClass({
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
            region: window.arcade.region,
            editing_region: false,
            new_region: '',
            area: window.arcade.area,
            editing_area: false,
            new_area: '',
            paseli_enabled_saving: false,
            paseli_infinite_saving: false,
            mask_services_url_saving: false,
            editing_machine: null,
            machines: window.machines,
            pcbcount: count_pcbids(window.machines),
            random_pcbid: {
                description: '',
            },
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
                    pcbcount: count_pcbids(response.machines),
                    events: response.events,
                });
                // Refresh every 5 seconds
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

    saveRegion: function(event) {
        AJAX.post(
            Link.get('update_region'),
            {region: this.state.new_region},
            function(response) {
                this.setState({
                    region: response.region,
                    new_region: '',
                    editing_region: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveArea: function(event) {
        AJAX.post(
            Link.get('update_area'),
            {area: this.state.new_area},
            function(response) {
                this.setState({
                    area: response.area,
                    new_area: '',
                    editing_area: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    togglePaseliEnabled: function() {
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
    },

    togglePaseliInfinite: function() {
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
    },

    toggleMaskServicesURL: function() {
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
                    <>
                        <span>{this.state.pin}</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_pin: true, new_pin: this.state.pin});
                            }.bind(this)}
                        />
                    </> :
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

    renderRegion: function() {
        return (
            <LabelledSection vertical={true} label="Region">{
                !this.state.editing_region ?
                    <>
                        <span>{ window.regions[this.state.region] }</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_region: true, new_region: this.state.region});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.saveRegion}>
                        <SelectInt
                            name="region"
                            value={ this.state.new_region }
                            choices={ window.regions }
                            onChange={function(choice) {
                                this.setState({new_region: event.target.value});
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
                                    new_region: '',
                                    editing_region: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    renderArea: function() {
        return (
            <LabelledSection vertical={true} label="Custom Area">{
                !this.state.editing_area ?
                    <>
                        <span>{ this.state.area ? this.state.area : <i>unset</i> }</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_area: true, new_area: this.state.area});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.saveArea}>
                        <input
                            type="text"
                            className="inline"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_area}
                            onChange={function(event) {
                                if (event.target.value.length <= 63) {
                                    this.setState({new_area: event.target.value});
                                }
                            }.bind(this)}
                            name="area"
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
                                    new_area: '',
                                    editing_area: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    generateNewMachine: function(event) {
        AJAX.post(
            Link.get('generatepcbid'),
            {machine: this.state.random_pcbid},
            function(response) {
                this.setState({
                    machines: response.machines,
                    pcbcount: count_pcbids(response.machines),
                    random_pcbid: {
                        description: '',
                    },
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    deleteExistingMachine: function(event, pcbid) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete PCBID',
            content: 'Are you sure you want to delete this PCBID from the network?',
            buttons: {
                Delete: {
                    btnClass: 'delete',
                    action: function() {
                        AJAX.post(
                            Link.get('removepcbid'),
                            {pcbid: pcbid},
                            function(response) {
                                this.setState({
                                    machines: response.machines,
                                    pcbcount: count_pcbids(response.machines),
                                });
                            }.bind(this)
                        );
                    }.bind(this),
                },
                Cancel: function() {
                },
            }
        });
        event.preventDefault();
    },

    saveMachine: function(event) {
        machine = this.state.editing_machine;
        if (machine.port == '') {
            machine.port = 0;
        }

        AJAX.post(
            Link.get('updatepcbid'),
            {machine: this.state.editing_machine},
            function(response) {
                this.setState({
                    machines: response.machines,
                    pcbcount: count_pcbids(response.machines),
                    editing_machine: null,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    renderDescription: function(machine) {
        if (this.state.editing_machine && machine.pcbid == this.state.editing_machine.pcbid) {
            return <input
                name="description"
                type="text"
                autofocus="true"
                ref={c => (this.focus_element = c)}
                value={ this.state.editing_machine.description }
                onChange={function(event) {
                    var machine = this.state.editing_machine;
                    machine.description = event.target.value;
                    this.setState({
                        editing_machine: machine,
                    });
                }.bind(this)}
            />;
        } else {
            return (
                <span>{ machine.description }</span>
            );
        }
    },

    renderPort: function(machine) {
        if (this.state.editing_machine && machine.pcbid == this.state.editing_machine.pcbid) {
            return <input
                name="port"
                type="text"
                value={ this.state.editing_machine.port }
                onChange={function(event) {
                    var machine = this.state.editing_machine;
                    var intRegex = /^\d*$/;
                    if (intRegex.test(event.target.value)) {
                        if (event.target.value.length > 0) {
                            machine.port = parseInt(event.target.value);
                        } else {
                            machine.port = '';
                        }
                        this.setState({
                            editing_machine: machine,
                        });
                    }
                }.bind(this)}
            />;
        } else {
            return (
                <span>{ machine.port }</span>
            );
        }
    },

    renderEditButton: function(machine) {
        if (this.state.editing_machine) {
            if (this.state.editing_machine.pcbid == machine.pcbid) {
                return (
                    <>
                        <input
                            type="submit"
                            value="save"
                        />
                        <input
                            type="button"
                            value="cancel"
                            onClick={function(event) {
                                this.setState({
                                    editing_machine: null,
                                });
                            }.bind(this)}
                        />
                    </>
                );
            } else {
                return null;
            }
        } else {
            if (window.max_pcbids > 0 && machine.editable) {
                return (
                    <>
                        <Edit
                            onClick={function(event) {
                                var editing_machine = null;
                                this.state.machines.map(function(a) {
                                    if (a.pcbid == machine.pcbid) {
                                        editing_machine = jQuery.extend(true, {}, a);
                                    }
                                });
                                this.setState({
                                    editing_machine: editing_machine,
                                });
                            }.bind(this)}
                        />
                        <Delete
                            onClick={function(event) {
                                this.deleteExistingMachine(event, machine.pcbid);
                            }.bind(this)}
                        />
                    </>
                );
            } else {
                return null;
            }
        }
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
                    {this.renderRegion()}
                    {this.renderArea()}
                    <LabelledSection vertical={true} label={
                        <>
                            PASELI Enabled
                            { this.state.paseli_enabled_saving ?
                                <img className="loading" src={Link.get('static', window.assets + 'loading-16.gif')} /> :
                                null
                            }
                        </>
                    }>
                        <Slider
                            on="yes"
                            off="no"
                            className="padded"
                            value={this.state.paseli_enabled}
                            onChange={function(value) {
                                this.togglePaseliEnabled();
                            }.bind(this)}
                        />
                    </LabelledSection>
                    <LabelledSection vertical={true} label={
                        <>
                            PASELI Infinite
                            { this.state.paseli_infinite_saving ?
                                <img className="loading" src={Link.get('static', window.assets + 'loading-16.gif')} /> :
                                null
                            }
                        </>
                    }>
                        <Slider
                            on="yes"
                            off="no"
                            className="padded"
                            value={this.state.paseli_infinite}
                            onChange={function(value) {
                                this.togglePaseliInfinite();
                            }.bind(this)}
                        />
                    </LabelledSection>
                    <LabelledSection vertical={true} label={
                        <>
                            Mask Web Address
                            { this.state.mask_services_url_saving ?
                                <img className="loading" src={Link.get('static', window.assets + 'loading-16.gif')} /> :
                                null
                            }
                        </>
                    }>
                        <Slider
                            on="yes"
                            off="no"
                            className="padded"
                            value={this.state.mask_services_url}
                            onChange={function(value) {
                                this.toggleMaskServicesURL();
                            }.bind(this)}
                        />
                    </LabelledSection>
                </div>
                <div className="section">
                    <h3>PCBIDs Assigned to This Arcade</h3>
                    <form className="inline" onSubmit={this.saveMachine}>
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
                                    render: this.renderDescription,
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
                                    render: this.renderPort,
                                    sort: function(a, b) { return a.port - b.port; },
                                },
                                {
                                    name: '',
                                    render: this.renderEditButton,
                                    hidden: !window.enforcing || window.max_pcbids < 1,
                                    action: true,
                                },
                            ]}
                            rows={this.state.machines}
                            emptymessage="There are no PCBIDs assigned to this arcade."
                        />
                    </form>
                </div>
                { window.enforcing && this.state.pcbcount < window.max_pcbids ?
                    <div className="section">
                        <h3>Generate PCBID</h3>
                        <form className="inline" onSubmit={this.generateNewMachine}>
                            <table className="add machine">
                                <thead>
                                    <tr>
                                        <th>Description</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>
                                            <input
                                                name="description"
                                                type="text"
                                                value={ this.state.random_pcbid.description }
                                                onChange={function(event) {
                                                    var pcbid = this.state.random_pcbid;
                                                    pcbid.description = event.target.value;
                                                    this.setState({random_pcbid: pcbid});
                                                }.bind(this)}
                                            />
                                        </td>
                                        <td>
                                            <input
                                                type="submit"
                                                value="generate PCBID"
                                            />
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </form>
                    </div>
                    : null
                }
                <div className="section">
                    <h3>Game Settings For This Arcade</h3>
                    <GameSettings game_settings={window.game_settings} />
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
