/*** @jsx React.DOM */

var card_management = createReactClass({
    getInitialState: function(props) {
        return {
            new_arcade: {
                name: '',
                description: '',
                region: window.default_region,
                area: window.default_area,
                paseli_enabled: window.paseli_enabled,
                paseli_infinite: window.paseli_infinite,
                mask_services_url: window.mask_services_url,
                owners: [null],
            },
            arcades: window.arcades,
            usernames: window.usernames,
            editing_arcade: null,
        };
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    addNewArcade: function(event) {
        AJAX.post(
            Link.get('addarcade'),
            {arcade: this.state.new_arcade},
            function(response) {
                this.setState({
                    arcades: response.arcades,
                    new_arcade: {
                        name: '',
                        description: '',
                        region: window.default_region,
                        area: window.default_area,
                        paseli_enabled: window.paseli_enabled,
                        paseli_infinite: window.paseli_infinite,
                        mask_services_url: window.mask_services_url,
                        owners: [null],
                    },
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveArcade: function(event) {
        AJAX.post(
            Link.get('updatearcade'),
            {arcade: this.state.editing_arcade},
            function(response) {
                this.setState({
                    arcades: response.arcades,
                    editing_arcade: null,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    deleteExistingArcade: function(event, arcadeid) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete Arcade',
            content: 'Are you sure you want to delete this arcade from the network?',
            buttons: {
                Delete: {
                    btnClass: 'delete',
                    action: function() {
                        AJAX.post(
                            Link.get('removearcade'),
                            {arcadeid: arcadeid},
                            function(response) {
                                this.setState({
                                    arcades: response.arcades,
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

    renderEditButton: function(arcade) {
        if(this.state.editing_arcade) {
            if (this.state.editing_arcade.id == arcade.id) {
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
                                    editing_arcade: null,
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
                            var editing_arcade = null;
                            this.state.arcades.map(function(a) {
                                if (a.id == arcade.id) {
                                    editing_arcade = jQuery.extend(true, {}, a);
                                    editing_arcade.owners.push(null);
                                }
                            });
                            this.setState({
                                editing_arcade: editing_arcade,
                            });
                        }.bind(this)}
                    />
                    <Delete
                        onClick={function(event) {
                            this.deleteExistingArcade(event, arcade.id);
                        }.bind(this)}
                    />
                </>
            );
        }
    },

    renderName: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return <input
                name="name"
                type="text"
                autofocus="true"
                ref={c => (this.focus_element = c)}
                value={ this.state.editing_arcade.name }
                onChange={function(event) {
                    var arcade = this.state.editing_arcade;
                    arcade.name = event.target.value;
                    this.setState({
                        editing_arcade: arcade,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ arcade.name }</span>;
        }
    },

    sortName: function(a, b) {
        return a.name.localeCompare(b.name);
    },

    renderDescription: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return <input
                name="description"
                type="text"
                value={ this.state.editing_arcade.description }
                onChange={function(event) {
                    var arcade = this.state.editing_arcade;
                    arcade.description = event.target.value;
                    this.setState({
                        editing_arcade: arcade,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ arcade.description }</span>;
        }
    },

    renderRegion: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return <SelectInt
                name="region"
                value={ this.state.editing_arcade.region }
                choices={ window.regions }
                onChange={function(choice) {
                    var arcade = this.state.editing_arcade;
                    arcade.region = event.target.value;
                    this.setState({editing_arcade: arcade});
                }.bind(this)}
            />;
        } else {
            return <span>{ window.regions[arcade.region] }</span>;
        }
    },

    renderArea: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return <input
                name="area"
                type="text"
                value={ this.state.editing_arcade.area }
                onChange={function(event) {
                    var arcade = this.state.editing_arcade;
                    arcade.area = event.target.value;
                    this.setState({
                        editing_arcade: arcade,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ arcade.area }</span>;
        }
    },

    sortDescription: function(a, b) {
        return a.description.localeCompare(b.description);
    },

    sortArea: function(a, b) {
        return a.area.localeCompare(b.area);
    },

    sortRegion: function(a, b) {
        return window.regions[a.region].localeCompare(window.regions[b.region]);
    },

    renderOwners: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return this.state.editing_arcade.owners.map(function(owner, index) {
                return (
                    <div>
                        <SelectUser
                            name="owner"
                            key={index}
                            value={ this.state.editing_arcade.owners[index] }
                            usernames={ this.state.usernames }
                            onChange={function(owner) {
                                var arcade = this.state.editing_arcade;
                                if (owner) {
                                    /* Update the owner */
                                    arcade.owners[index] = owner;
                                    if (arcade.owners[arcade.owners.length - 1]) {
                                        arcade.owners.push(null);
                                    }
                                } else {
                                    /* We should kill this if there is more
                                       than one owner. */
                                    if (arcade.owners.length > 1) {
                                        arcade.owners.splice(index, 1);
                                    } else {
                                        arcade.owners[index] = null;
                                    }
                                }
                                this.setState({
                                    editing_arcade: arcade,
                                });
                            }.bind(this)}
                        />
                    </div>
                );
            }.bind(this))
        } else {
            return (
                (arcade.owners.length > 0) ?
                    <ul className="ownerlist">{
                        arcade.owners.map(function(owner) {
                            return <li>{ owner }</li>;
                        }.bind(this))
                    }</ul> :
                    <span className="placeholder">nobody</span>
            );
        }
    },

    renderPaseliEnabled: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return <input
                name="paseli_enabled"
                type="checkbox"
                checked={ this.state.editing_arcade.paseli_enabled }
                onChange={function(event) {
                    var arcade = this.state.editing_arcade;
                    arcade.paseli_enabled = event.target.checked;
                    this.setState({
                        editing_arcade: arcade,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ arcade.paseli_enabled ? "yes" : "no"  }</span>;
        }
    },

    renderPaseliInfinite: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return <input
                name="paseli_infinite"
                type="checkbox"
                checked={ this.state.editing_arcade.paseli_infinite }
                onChange={function(event) {
                    var arcade = this.state.editing_arcade;
                    arcade.paseli_infinite = event.target.checked;
                    this.setState({
                        editing_arcade: arcade,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ arcade.paseli_infinite ? "yes" : "no"  }</span>;
        }
    },

    renderMaskServicesURL: function(arcade) {
        if (this.state.editing_arcade && arcade.id == this.state.editing_arcade.id) {
            return <input
                name="mask_services_url"
                type="checkbox"
                checked={ this.state.editing_arcade.mask_services_url }
                onChange={function(event) {
                    var arcade = this.state.editing_arcade;
                    arcade.mask_services_url = event.target.checked;
                    this.setState({
                        editing_arcade: arcade,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ arcade.mask_services_url ? "yes" : "no"  }</span>;
        }
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    <form className="inline" onSubmit={this.saveArcade}>
                        <Table
                            className="list arcade"
                            columns={[
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
                                    name: "Region",
                                    render: this.renderRegion,
                                    sort: this.sortRegion,
                                },
                                {
                                    name: "Custom Area",
                                    render: this.renderArea,
                                    sort: this.sortArea,
                                },
                                {
                                    name: 'Owners',
                                    render: this.renderOwners,
                                },
                                {
                                    name: 'PASELI Enabled',
                                    render: this.renderPaseliEnabled,
                                },
                                {
                                    name: 'PASELI Infinite',
                                    render: this.renderPaseliInfinite,
                                },
                                {
                                    name: 'Mask Web Address',
                                    render: this.renderMaskServicesURL,
                                },
                                {
                                    name: '',
                                    render: this.renderEditButton,
                                    action: true,
                                },
                            ]}
                            rows={this.state.arcades}
                            emptymessage="There are no arcades on this network."
                        />
                    </form>
                </div>
                <div className="section">
                    <h3>Add Arcade</h3>
                    <form className="inline" onSubmit={this.addNewArcade}>
                        <table className="add arcade">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Description</th>
                                    <th>Region</th>
                                    <th>Custom Area</th>
                                    <th>Owners</th>
                                    <th>PASELI Enabled</th>
                                    <th>PASELI Infinite</th>
                                    <th>Mask Web Address</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>
                                        <input
                                            name="name"
                                            type="text"
                                            value={ this.state.new_arcade.name }
                                            onChange={function(event) {
                                                var arcade = this.state.new_arcade;
                                                arcade.name = event.target.value;
                                                this.setState({new_arcade: arcade});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            name="description"
                                            type="text"
                                            value={ this.state.new_arcade.description }
                                            onChange={function(event) {
                                                var arcade = this.state.new_arcade;
                                                arcade.description = event.target.value;
                                                this.setState({new_arcade: arcade});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <SelectInt
                                            name="region"
                                            value={ this.state.new_arcade.region }
                                            choices={ window.regions }
                                            onChange={function(choice) {
                                                var arcade = this.state.new_arcade;
                                                arcade.region = event.target.value;
                                                this.setState({new_arcade: arcade});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            name="area"
                                            type="text"
                                            value={ this.state.new_arcade.area }
                                            onChange={function(event) {
                                                var arcade = this.state.new_arcade;
                                                arcade.area = event.target.value;
                                                this.setState({new_arcade: arcade});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>{
                                        this.state.new_arcade.owners.map(function(owner, index) {
                                            return (
                                                <div>
                                                    <SelectUser
                                                        name="owner"
                                                        key={index}
                                                        value={ this.state.new_arcade.owners[index] }
                                                        usernames={ this.state.usernames }
                                                        onChange={function(owner) {
                                                            var arcade = this.state.new_arcade;
                                                            if (owner) {
                                                                /* Update the owner */
                                                                arcade.owners[index] = owner;
                                                                if (arcade.owners[arcade.owners.length - 1]) {
                                                                    arcade.owners.push(null);
                                                                }
                                                            } else {
                                                                /* We should kill this if there is more
                                                                   than one owner. */
                                                                if (arcade.owners.length > 1) {
                                                                    arcade.owners.splice(index, 1);
                                                                } else {
                                                                    arcade.owners[index] = null;
                                                                }
                                                            }
                                                            this.setState({
                                                                new_arcade: arcade,
                                                            });
                                                        }.bind(this)}
                                                    />
                                                </div>
                                            );
                                        }.bind(this))
                                    }</td>
                                    <td>
                                        <input
                                            name="paseli_enabled"
                                            type="checkbox"
                                            checked={ this.state.new_arcade.paseli_enabled }
                                            onChange={function(event) {
                                                var arcade = this.state.new_arcade;
                                                arcade.paseli_enabled = event.target.checked;
                                                this.setState({
                                                    new_arcade: arcade,
                                                });
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            name="paseli_infinite"
                                            type="checkbox"
                                            checked={ this.state.new_arcade.paseli_infinite }
                                            onChange={function(event) {
                                                var arcade = this.state.new_arcade;
                                                arcade.paseli_infinite = event.target.checked;
                                                this.setState({
                                                    new_arcade: arcade,
                                                });
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            name="mask_services_url"
                                            type="checkbox"
                                            checked={ this.state.new_arcade.mask_services_url }
                                            onChange={function(event) {
                                                var arcade = this.state.new_arcade;
                                                arcade.mask_services_url = event.target.checked;
                                                this.setState({
                                                    new_arcade: arcade,
                                                });
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            type="submit"
                                            value="add arcade"
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
    React.createElement(card_management, null),
    document.getElementById('content')
);
