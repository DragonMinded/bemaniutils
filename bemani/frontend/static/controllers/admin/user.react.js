/*** @jsx React.DOM */

var user_management = createReactClass({
    getInitialState: function(props) {
        var credits = {};
        Object.keys(window.arcades).map(function(arcadeid) {
            credits[arcadeid] = '';
        });
        return {
            editing_email: false,
            email: window.user.email,
            new_email: window.user.email,
            editing_username: false,
            username: window.user.username,
            new_username: window.user.username,
            editing_pin: false,
            new_pin: '',
            editing_password: false,
            new_password1: '',
            new_password2: '',
            cards: window.cards,
            new_card: '',
            balances: window.balances,
            credits: credits,
            arcades: window.arcades,
            events: window.events,
            eventoffset: 0,
            eventlimit: 5,
        };
    },

    componentDidMount: function() {
        this.refreshUser();
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    refreshUser: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    cards: response.cards,
                    balances: response.balances,
                    arcades: response.arcades,
                    events: response.events,
                });
                // Refresh every 15 seconds
                setTimeout(this.refreshUser, 5000);
            }.bind(this)
        );
    },

    deleteExistingCard: function(card) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete Card',
            content: 'Are you sure you want to delete this card from this account?',
            buttons: {
                Delete: {
                    btnClass: 'delete',
                    action: function() {
                        AJAX.post(
                            Link.get('removeusercard'),
                            {card: card},
                            function(response) {
                                this.setState({
                                    cards: response.cards,
                                });
                            }.bind(this)
                        );
                    }.bind(this),
                },
                Cancel: function() {
                },
            }
        });
    },

    addNewCard: function(event) {
        AJAX.post(
            Link.get('addusercard'),
            {card: this.state.new_card},
            function(response) {
                this.setState({
                    cards: response.cards,
                    new_card: '',
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    updateBalance: function(event) {
        var updates = {};
        Object.keys(this.state.credits).map(function(arcadeid) {
            var intval = parseInt(this.state.credits[arcadeid]);
            if (!isNaN(intval)) {
                updates[arcadeid] = intval;
            }
        }.bind(this));
        AJAX.post(
            Link.get('updatebalance'),
            {credits: updates},
            function(response) {
                var credits = {};
                Object.keys(response.arcades).map(function(arcadeid) {
                    credits[arcadeid] = '';
                });
                this.setState({
                    arcades: response.arcades,
                    balances: response.balances,
                    credits: credits,
                    events: response.events,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveUsername: function(event) {
        AJAX.post(
            Link.get('updateusername'),
            {
                username: this.state.new_username,
            },
            function(response) {
                this.setState({
                    username: response.username,
                    new_username: response.username,
                    editing_username: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveEmail: function(event) {
        AJAX.post(
            Link.get('updateemail'),
            {
                email: this.state.new_email,
            },
            function(response) {
                this.setState({
                    email: response.email,
                    new_email: response.email,
                    editing_email: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    savePin: function(event) {
        AJAX.post(
            Link.get('updatepin'),
            {pin: this.state.new_pin},
            function(response) {
                this.setState({
                    new_pin: '',
                    editing_pin: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    savePassword: function(event) {
        AJAX.post(
            Link.get('updatepassword'),
            {
                new1: this.state.new_password1,
                new2: this.state.new_password2,
            },
            function(response) {
                this.setState({
                    new_password1: '',
                    new_password2: '',
                    editing_password: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    renderUsername: function() {
        return (
            <LabelledSection vertical={true} label="Username">{
                !this.state.editing_username ?
                    <>
                        {
                            this.state.username ?
                                <span>{ this.state.username }</span> :
                                <span className="placeholder">unset</span>
                        }
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_username: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.saveUsername}>
                        <input
                            type="text"
                            className="inline"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_username}
                            onChange={function(event) {
                                this.setState({new_username: event.target.value});
                            }.bind(this)}
                            name="username"
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
                                    new_username: this.state.username,
                                    editing_username: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    renderPassword: function() {
        return (
            <LabelledSection vertical={true} label="Password">{
                !this.state.editing_password ?
                    <>
                        <span>&bull;&bull;&bull;&bull;&bull;&bull;</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_password: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.savePassword}>
                        <div>
                            <label htmlFor="new1">New password:</label>
                            <input
                                type="password"
                                autofocus="true"
                                ref={c => (this.focus_element = c)}
                                value={this.state.new_password1}
                                onChange={function(event) {
                                    this.setState({new_password1: event.target.value});
                                }.bind(this)}
                                name="new1"
                            />
                        </div>
                        <div>
                            <label htmlFor="new2">New password (again):</label>
                            <input
                                type="password"
                                value={this.state.new_password2}
                                onChange={function(event) {
                                    this.setState({new_password2: event.target.value});
                                }.bind(this)}
                                name="new2"
                            />
                        </div>
                        <div className="buttons">
                            <input
                                type="submit"
                                value="save"
                            />
                            <input
                                type="button"
                                value="cancel"
                                onClick={function(event) {
                                    this.setState({
                                        new_password1: '',
                                        new_password2: '',
                                        editing_password: false,
                                    });
                                }.bind(this)}
                            />
                        </div>
                    </form>
            }</LabelledSection>
        );
    },

    renderEmail: function() {
        return (
            <LabelledSection vertical={true} label="Email Address">{
                !this.state.editing_email ?
                    <>
                        {
                            this.state.email ?
                                <span>{ this.state.email }</span> :
                                <span className="placeholder">unset</span>
                        }
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_email: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.saveEmail}>
                        <input
                            type="text"
                            className="inline"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_email}
                            onChange={function(event) {
                                this.setState({new_email: event.target.value});
                            }.bind(this)}
                            name="email"
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
                                    new_email: this.state.email,
                                    editing_email: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    renderPIN: function() {
        return (
            <LabelledSection vertical={true} label="PIN">{
                !this.state.editing_pin ?
                    <>
                        <span>&bull;&bull;&bull;&bull;</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_pin: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.savePin}>
                        <input
                            type="text"
                            maxlength="4"
                            size="4"
                            className="inline"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_pin}
                            onChange={function(event) {
                                var intRegex = /^\d*$/;
                                if (event.target.value.length <= 4 && intRegex.test(event.target.value)) {
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
                    <h3>User Details</h3>
                    {this.renderUsername()}
                    {this.renderPassword()}
                    {this.renderEmail()}
                    {this.renderPIN()}
                </div>
                <div className="section">
                    <h3>Cards</h3>
                    {this.state.cards.map(function(card) {
                        return (
                            <div>
                                <Card number={card} />
                                <Delete
                                    onClick={this.deleteExistingCard.bind(this, card)}
                                />
                            </div>
                        );
                    }.bind(this))}
                </div>
                <div className="section">
                    <h3>Add Card</h3>
                    <form onSubmit={this.addNewCard}>
                        <input
                            type="text"
                            className="inline"
                            value={this.state.new_card}
                            onChange={function(event) {
                                this.setState({new_card: event.target.value});
                            }.bind(this)}
                            name="card_number"
                        />
                        <input type="submit" value="add card" />
                    </form>
                </div>
                <div className="section">
                    <h3>PASELI Balance</h3>
                    { Object.keys(this.state.arcades).length == 0 ?
                        <div>
                            <span className="placeholder">No arcades present!</span>
                        </div> :
                        <form onSubmit={this.updateBalance}>
                            <Table
                                className="list balance"
                                columns={[
                                    {
                                        name: 'Arcade',
                                        render: function(arcadeid) {
                                            return this.state.arcades[arcadeid];
                                        }.bind(this),
                                        sort: function(a, b) {
                                            return this.state.arcades[a].localeCompare(this.state.arcades[b]);
                                        }.bind(this),
                                    },
                                    {
                                        name: 'Current Balance',
                                        render: function(arcadeid) {
                                            return this.state.balances[arcadeid];
                                        }.bind(this),
                                    },
                                    {
                                        name: 'Credit Amount',
                                        render: function(arcadeid) {
                                            return (
                                                <input
                                                    type="text"
                                                    className="inline"
                                                    value={this.state.credits[arcadeid]}
                                                    onChange={function(event) {
                                                        var credits = this.state.credits;
                                                        credits[arcadeid] = event.target.value;
                                                        this.setState({credits: credits});
                                                    }.bind(this)}
                                                    name="credits"
                                                />
                                            );
                                        }.bind(this),
                                    }
                                ]}
                                rows={Object.keys(this.state.arcades)}
                                emptymessage="There are no arcades on this network."
                            />
                            <div className="action">
                                <input type="submit" value="update balance" />
                            </div>
                        </form>
                    }
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
                                        return <PASELITransactionEvent event={event} arcades={this.state.arcades} />;
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
    React.createElement(user_management, null),
    document.getElementById('content')
);
