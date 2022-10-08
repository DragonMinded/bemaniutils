/*** @jsx React.DOM */

var machine_management = createReactClass({
    getInitialState: function(props) {
        return {
            machines: window.machines,
            arcades: window.arcades,
            editing_machine: null,
            add_machine: {
                pcbid: '',
                name: '',
                description: '',
                arcade: null,
            },
            random_pcbid: {
                name: '',
                description: '',
                arcade: null,
            },
        };
    },

    componentDidMount: function() {
        this.refreshMachines();
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    refreshMachines: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    machines: response.machines,
                    arcade: response.arcades,
                });
                // Refresh every 5 seconds
                setTimeout(this.refreshMachines, 5000);
            }.bind(this)
        );
    },

    generateNewMachine: function(event) {
        AJAX.post(
            Link.get('generatepcbid'),
            {machine: this.state.random_pcbid},
            function(response) {
                this.setState({
                    machines: response.machines,
                    random_pcbid: {
                        name: '',
                        description: '',
                        arcade: null,
                    },
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    addNewMachine: function(event) {
        AJAX.post(
            Link.get('addpcbid'),
            {machine: this.state.add_machine},
            function(response) {
                this.setState({
                    machines: response.machines,
                    add_machine: {
                        pcbid: '',
                        name: '',
                        description: '',
                        arcade: null,
                    },
                });
            }.bind(this)
        );
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
                    editing_machine: null,
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

    renderPCBID: function(machine) {
        return (
            <span>{ machine.pcbid }</span>
        );
    },

    sortPCBID: function(a, b) {
        return a.pcbid.localeCompare(b.pcbid);
    },

    renderName: function(machine) {
        return (
            <span>{ machine.name }</span>
        );
    },

    sortName: function(a, b) {
        return a.name.localeCompare(b.name);
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

    sortDescription: function(a, b) {
        return a.description.localeCompare(b.description);
    },

    renderSeriesList: function(machine) {
        return (
            <select
                name="game"
                value={this.state.editing_machine.game}
                onChange={function(event) {
                    var machine = this.state.editing_machine;
                    machine.game = event.target.value;
                    this.setState({
                        editing_machine: machine,
                    });
                }.bind(this)}
            >
                {Object.keys(window.series).map(function(key, index) {
                    return <option value={key}>{ window.series[key] }</option>;
                }.bind(this))}
            </select>
        );
    },

    renderGameList: function(machine, negate) {
        return (
            <select
                name="game"
                value={this.state.editing_machine.game + '_' + this.state.editing_machine.version}
                onChange={function(event) {
                    var data = event.target.value.split('_');
                    var machine = this.state.editing_machine;
                    machine.game = data[0];
                    machine.version = parseInt(data[1]);
                    this.setState({
                        editing_machine: machine,
                    });
                }.bind(this)}
            >
                {Object.keys(window.games).map(function(game) {
                    return Object.keys(window.games[game]).map(function(version) {
                        if (negate) {
                            version = -version;
                        }
                        return <option value={game + '_' + version}>{ window.games[game][Math.abs(version)] }</option>;
                    }.bind(this));
                }.bind(this))}
            </select>
        );
    },

    renderGame: function(machine) {
        if (this.state.editing_machine && machine.pcbid == this.state.editing_machine.pcbid) {
            var value;
            var extra;

            if (this.state.editing_machine.game == 'any') {
                value = 'any';
                extra = null;
            } else if(!this.state.editing_machine.version) {
                value = 'series';
                extra = this.renderSeriesList(machine);
            } else if(this.state.editing_machine.version > 0) {
                value = 'exact';
                extra = this.renderGameList(machine, false);
            } else if(this.state.editing_machine.version < 0) {
                value = 'atmost';
                extra = this.renderGameList(machine, true);
            };

            return (
                <>
                    <select
                        name="function"
                        value={value}
                        onChange={function(event) {
                            var nv = event.target.value;
                            var machine = this.state.editing_machine;
                            if (nv == 'any') {
                                machine.game = 'any';
                                machine.version = null;
                            } else if(nv == 'series') {
                                machine.game = Object.keys(window.series)[0];
                                machine.version = null;
                            } else if(nv == 'exact') {
                                machine.game = Object.keys(window.series)[0];
                                machine.version = Object.keys(window.games[machine.game])[0];
                            } else if(nv == 'atmost') {
                                machine.game = Object.keys(window.series)[0];
                                machine.version = -Object.keys(window.games[machine.game])[0];
                            }
                            this.setState({
                                editing_machine: machine,
                            });
                        }.bind(this)}
                    >
                        <option value="any">any supported game</option>
                        <option value="series">specific series</option>
                        <option value="exact">specific game</option>
                        <option value="atmost">specific game or older</option>
                    </select>
                    {extra}
                </>
            );
        } else {
            if (machine.game == 'any') {
                return (
                    <span>any game</span>
                );
            } else if(!machine.version) {
                return (
                    <span>{ window.series[machine.game] }</span>
                );
            } else if(machine.version > 0) {
                return (
                    <span>{ window.games[machine.game][machine.version] }</span>
                );
            } else if(machine.version < 0) {
                return (
                    <span>{ window.games[machine.game][-machine.version] } or older</span>
                );
            }
        }
    },

    sortGame: function(a, b) {
        var ag = null;
        var bg = null;
        if (a.game == 'any') {
            ag = 'any game';
        } else if(!a.version) {
            ag = window.series[a.game];
        } else if(a.version > 0) {
            ag = window.games[a.game][a.version];
        } else if(a.version < 0) {
            ag = window.games[a.game][-a.version] + ' or older';
        }
        if (b.game == 'any') {
            bg = 'any game';
        } else if(!b.version) {
            bg = window.series[b.game];
        } else if(b.version > 0) {
            bg = window.games[b.game][b.version];
        } else if(b.version < 0) {
            bg = window.games[b.game][-b.version] + ' or older';
        }
        return ag.localeCompare(bg);
    },

    renderArcade: function(machine) {
        if (this.state.editing_machine && machine.pcbid == this.state.editing_machine.pcbid) {
            return (
                <SelectArcade
                    name="owner"
                    value={ this.state.editing_machine.arcade }
                    arcades={ this.state.arcades }
                    onChange={function(owner) {
                        var machine = this.state.editing_machine;
                        machine.arcade = parseInt(owner);
                        this.setState({
                            editing_machine: machine,
                         });
                     }.bind(this)}
                 />
             );
        } else {
            if (machine.arcade) {
                return (
                    <span>{ this.state.arcades[machine.arcade] }</span>
                );
            } else {
                return (
                    <span className="placeholder">no arcade</span>
                );
            }
        }
    },

    sortArcade: function(a, b) {
        var aarc = this.state.arcades[a.arcade];
        var barc = this.state.arcades[b.arcade];
        aarc = aarc ? aarc : '';
        barc = barc ? barc : '';
        return aarc.localeCompare(barc);
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

    sortPort: function(a, b) {
        return a.port - b.port;
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
        }
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    <form className="inline" onSubmit={this.saveMachine}>
                        <Table
                            className="list machines"
                            columns={[
                                {
                                    name: 'PCBID',
                                    render: this.renderPCBID,
                                    sort: this.sortPCBID,
                                },
                                {
                                    name: 'Name',
                                    render: this.renderName,
                                    sort: this.sortName,
                                },
                                {
                                    name: 'Description',
                                    render: this.renderDescription,
                                    sort: this.sortDescription,
                                },
                                {
                                    name: 'Arcade',
                                    render: this.renderArcade,
                                    sort: this.sortArcade,
                                },
                                {
                                    name: 'Applicable Game',
                                    render: this.renderGame,
                                    sort: this.sortGame,
                                    hidden: !window.enforcing,
                                },
                                {
                                    name: 'Port',
                                    render: this.renderPort,
                                    sort: this.sortPort,
                                },
                                {
                                    name: '',
                                    render: this.renderEditButton,
                                    action: true,
                                },
                            ]}
                            rows={this.state.machines}
                            emptymessage="There are no PCBIDs assigned to this network."
                        />
                    </form>
                </div>
                <div className="section">
                    <h3>Add PCBID</h3>
                    <form className="inline" onSubmit={this.addNewMachine}>
                        <table className="add machine">
                            <thead>
                                <tr>
                                    <th>PCBID</th>
                                    <th>Description</th>
                                    <th>Arcade</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>
                                        <input
                                            name="pcbid"
                                            type="text"
                                            value={ this.state.add_machine.pcbid }
                                            onChange={function(event) {
                                                var machine = this.state.add_machine;
                                                machine.pcbid = event.target.value;
                                                this.setState({add_machine: machine});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            name="description"
                                            type="text"
                                            value={ this.state.add_machine.description }
                                            onChange={function(event) {
                                                var machine = this.state.add_machine;
                                                machine.description = event.target.value;
                                                this.setState({add_machine: machine});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <SelectArcade
                                            name="owner"
                                            value={ this.state.add_machine.arcade }
                                            arcades={ this.state.arcades }
                                            onChange={function(owner) {
                                                var machine = this.state.add_machine;
                                                machine.arcade = parseInt(owner);
                                                this.setState({
                                                    add_machine: machine,
                                                 });
                                             }.bind(this)}
                                         />
                                    </td>
                                    <td>
                                        <input
                                            type="submit"
                                            value="add PCBID"
                                        />
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </form>
                </div>
                <div className="section">
                    <h3>Generate Random PCBID</h3>
                    <form className="inline" onSubmit={this.generateNewMachine}>
                        <table className="add machine">
                            <thead>
                                <tr>
                                    <th>Description</th>
                                    <th>Arcade</th>
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
                                        <SelectArcade
                                            name="owner"
                                            value={ this.state.random_pcbid.arcade }
                                            arcades={ this.state.arcades }
                                            onChange={function(owner) {
                                                var arcade = this.state.random_pcbid;
                                                arcade.arcade = parseInt(owner);
                                                this.setState({
                                                    random_pcbid: arcade,
                                                 });
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
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(machine_management, null),
    document.getElementById('content')
);
