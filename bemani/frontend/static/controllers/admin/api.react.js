/*** @jsx React.DOM */

var api_management = createReactClass({
    getInitialState: function(props) {
        var info = this.scheduleServerInfo(window.servers);
        return {
            new_client: {
                name: '',
            },
            new_server: {
                uri: 'https://',
                token: '',
            },
            info: info,
            clients: window.clients,
            servers: window.servers,
            editing_client: null,
            editing_server: null,
        };
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    scheduleServerInfo: function(servers) {
        var info = {};

        servers.map(function(server) {
            if (this.state && this.state.info[server.id]) {
                // We already got this info
                info[server.id] = this.state.info[server.id];
                return;
            }

            // We don't have this looked up yet
            info[server.id] = {loading: true};
            AJAX.get(
               Link.get('queryserver', server.id),
               function(response) {
                   var sinfo = this.state.info;
                   sinfo[server.id] = response;
                   sinfo[server.id].loading = false;
                   this.setState({info: sinfo});
               }.bind(this)
            );
        }.bind(this));

        return info;
    },

    addNewClient: function(event) {
        AJAX.post(
            Link.get('addclient'),
            {client: this.state.new_client},
            function(response) {
                this.setState({
                    clients: response.clients,
                    new_client: {
                        name: '',
                    },
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveClient: function(event) {
        AJAX.post(
            Link.get('updateclient'),
            {client: this.state.editing_client},
            function(response) {
                this.setState({
                    clients: response.clients,
                    editing_client: null,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    deleteExistingClient: function(event, clientid) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete Client',
            content: 'Are you sure you want to delete and de-auth this client from the network?',
            buttons: {
                Delete: {
                    btnClass: 'delete',
                    action: function() {
                        AJAX.post(
                            Link.get('removeclient'),
                            {clientid: clientid},
                            function(response) {
                                this.setState({
                                    clients: response.clients,
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

    addNewServer: function(event) {
        AJAX.post(
            Link.get('addserver'),
            {server: this.state.new_server},
            function(response) {
                // Schedule probe of new server just added
                var info = this.scheduleServerInfo(response.servers);
                this.setState({
                    servers: response.servers,
                    info: info,
                    new_server: {
                        uri: 'https://',
                        token: '',
                    },
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveServer: function(event) {
        var serverid = this.state.editing_server.id;
        AJAX.post(
            Link.get('updateserver'),
            {server: this.state.editing_server},
            function(response) {
                // Kill our existing info so we can refresh with changes
                delete this.state.info[serverid];
                var info = this.scheduleServerInfo(response.servers);
                this.setState({
                    info: info,
                    servers: response.servers,
                    editing_server: null,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    deleteExistingServer: function(event, serverid) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete Server',
            content: 'Are you sure you want to delete this remote server from the network?',
            buttons: {
                Delete: {
                    btnClass: 'delete',
                    action: function() {
                        AJAX.post(
                            Link.get('removeserver'),
                            {serverid: serverid},
                            function(response) {
                                // Kill the entry we no longer need
                                var info = this.state.info;
                                delete info[serverid];
                                this.setState({
                                    info: info,
                                    servers: response.servers,
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

    renderClientEditButton: function(client) {
        if(this.state.editing_client) {
            if (this.state.editing_client.id == client.id) {
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
                                    editing_client: null,
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
                            var editing_client = null;
                            this.state.clients.map(function(a) {
                                if (a.id == client.id) {
                                    editing_client = jQuery.extend(true, {}, a);
                                }
                            });
                            this.setState({
                                editing_client: editing_client,
                            });
                        }.bind(this)}
                    />
                    <Delete
                        onClick={function(event) {
                            this.deleteExistingClient(event, client.id);
                        }.bind(this)}
                    />
                </>
            );
        }
    },

    renderClientName: function(client) {
        if (this.state.editing_client && client.id == this.state.editing_client.id) {
            return <input
                name="name"
                type="text"
                autofocus="true"
                ref={c => (this.focus_element = c)}
                value={ this.state.editing_client.name }
                onChange={function(event) {
                    var client = this.state.editing_client;
                    client.name = event.target.value;
                    this.setState({
                        editing_client: client,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ client.name }</span>;
        }
    },

    sortClientName: function(a, b) {
        return a.name.localeCompare(b.name);
    },

    renderClientToken: function(client) {
        return <span>{ client.token }</span>;
    },

    sortClientToken: function(a, b) {
        return a.token.localeCompare(b.token);
    },

    renderServerEditButton: function(server) {
        if(this.state.editing_server) {
            if (this.state.editing_server.id == server.id) {
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
                                    editing_server: null,
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
                            var editing_server = null;
                            this.state.servers.map(function(a) {
                                if (a.id == server.id) {
                                    editing_server = jQuery.extend(true, {}, a);
                                }
                            });
                            this.setState({
                                editing_server: editing_server,
                            });
                        }.bind(this)}
                    />
                    <Delete
                        onClick={function(event) {
                            this.deleteExistingServer(event, server.id);
                        }.bind(this)}
                    />
                </>
            );
        }
    },

    renderServerURI: function(server) {
        if (this.state.editing_server && server.id == this.state.editing_server.id) {
            return <input
                name="uri"
                type="text"
                autofocus="true"
                ref={c => (this.focus_element = c)}
                value={ this.state.editing_server.uri }
                onChange={function(event) {
                    var server = this.state.editing_server;
                    server.uri = event.target.value;
                    this.setState({
                        editing_server: server,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ server.uri }</span>;
        }
    },

    sortServerURI: function(a, b) {
        return a.uri.localeCompare(b.uri);
    },

    renderServerToken: function(server) {
        if (this.state.editing_server && server.id == this.state.editing_server.id) {
            return <input
                name="token"
                type="text"
                value={ this.state.editing_server.token }
                onChange={function(event) {
                    var server = this.state.editing_server;
                    server.token = event.target.value;
                    this.setState({
                        editing_server: server,
                    });
                }.bind(this)}
            />;
        } else {
            return <span>{ server.token }</span>;
        }
    },

    sortServerToken: function(a, b) {
        return a.token.localeCompare(b.token);
    },

    renderServerInfo: function(server) {
        if (!this.state.info[server.id]) {
            return <span className='placeholder'>No info!</span>;
        }
        if (this.state.info[server.id].loading) {
            return (
                <>
                     <img className="loading" src={Link.get('static', window.assets + 'loading-16.gif')} />
                     {' querying server for info...'}
                 </>
             );
        }
        if (this.state.info[server.id].status == 'badauth') {
            return (
                <span>Invalid auth token provided!</span>
            );
        }
        if (this.state.info[server.id].status == 'error') {
            return (
                <span>Error requesting server info!</span>
            );
        }

        return (
            <>
                <div>
                    <b>{this.state.info[server.id].name}</b>
                    {' administered by '}
                    <a href={'mailto:' + this.state.info[server.id].email}>{this.state.info[server.id].email}</a>
                </div>
                { this.state.info[server.id].status == 'badversion' ?
                    <span className='placeholder'>This server supports an incompatible version of the API!</span> : null
                }
            </>
        );
    },

    renderServerAllowedData: function(server) {
        if (this.state.editing_server && server.id == this.state.editing_server.id) {
            return (
                <>
                    <div>
                        <input
                            name="stats"
                            id="stats"
                            type="checkbox"
                            checked={ this.state.editing_server.allow_stats }
                            onChange={function(event) {
                                var server = this.state.editing_server;
                                server.allow_stats = event.target.checked;
                                this.setState({
                                    editing_server: server,
                                });
                            }.bind(this)}
                        />
                        <label htmlFor="stats">play statistics</label>
                    </div>
                    <div>
                        <input
                            name="scores"
                            id="scores"
                            type="checkbox"
                            checked={ this.state.editing_server.allow_scores }
                            onChange={function(event) {
                                var server = this.state.editing_server;
                                server.allow_scores = event.target.checked;
                                this.setState({
                                    editing_server: server,
                                });
                            }.bind(this)}
                        />
                        <label htmlFor="scores">rivals and scores</label>
                    </div>
                </>
            );
        } else {
            if (!server.allow_stats && !server.allow_scores) {
                return <span className="placeholder">remote data fetching disabled</span>;
            }
            var enabled = [];
            if (server.allow_stats) {
                enabled.push('play statistics');
            }
            if (server.allow_scores) {
                enabled.push('rivals');
                enabled.push('scores');
            }
            return <span>{ enabled.join(', ') }</span>;
        }
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    <h3>Authorized Clients</h3>
                    <form className="inline" onSubmit={this.saveClient}>
                        <Table
                            className="list client"
                            columns={[
                                {
                                    name: 'Name',
                                    render: this.renderClientName,
                                    sort: this.sortClientName,
                                },
                                {
                                    name: 'Auth Token',
                                    render: this.renderClientToken,
                                    sort: this.sortClientToken,
                                },
                                {
                                    name: '',
                                    render: this.renderClientEditButton,
                                    action: true,
                                },
                            ]}
                            rows={this.state.clients}
                            emptymessage="There are no clients authorized to talk to this network."
                        />
                    </form>
                </div>
                <div className="section">
                    <h3>Add Client</h3>
                    <form className="inline" onSubmit={this.addNewClient}>
                        <table className="add client">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>
                                        <input
                                            name="name"
                                            type="text"
                                            value={ this.state.new_client.name }
                                            onChange={function(event) {
                                                var client = this.state.new_client;
                                                client.name = event.target.value;
                                                this.setState({new_client: client});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            type="submit"
                                            value="add client"
                                        />
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </form>
                </div>
                <div className="section">
                    <h3>Remote Servers</h3>
                    <form className="inline" onSubmit={this.saveServer}>
                        <Table
                            className="list server"
                            columns={[
                                {
                                    name: 'URI',
                                    render: this.renderServerURI,
                                    sort: this.sortServerURI,
                                },
                                {
                                    name: 'Auth Token',
                                    render: this.renderServerToken,
                                    sort: this.sortServerToken,
                                },
                                {
                                    name: 'Server Info',
                                    render: this.renderServerInfo,
                                },
                                {
                                    name: 'Allowed Data',
                                    render: this.renderServerAllowedData,
                                },
                                {
                                    name: '',
                                    render: this.renderServerEditButton,
                                    action: true,
                                },
                            ]}
                            rows={this.state.servers}
                            emptymessage="There are no remote servers on this network."
                        />
                    </form>
                </div>
                <div className="section">
                    <h3>Add Remote Server</h3>
                    <form className="inline" onSubmit={this.addNewServer}>
                        <table className="add server">
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Token</th>
                                    <th></th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>
                                        <input
                                            name="uri"
                                            type="text"
                                            value={ this.state.new_server.uri }
                                            onChange={function(event) {
                                                var server = this.state.new_server;
                                                server.uri = event.target.value;
                                                this.setState({new_server: server});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            name="token"
                                            type="text"
                                            value={ this.state.new_server.token }
                                            onChange={function(event) {
                                                var server = this.state.new_server;
                                                server.token = event.target.value;
                                                this.setState({new_server: server});
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input
                                            type="submit"
                                            value="add server"
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
    React.createElement(api_management, null),
    document.getElementById('content')
);
