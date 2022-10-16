/*** @jsx React.DOM */

var card_management = createReactClass({
    getInitialState: function(props) {
        return {
            cards: window.cards,
            usernames: window.usernames,
            new_card: {
                number: '',
                owner: null,
            },
        };
    },

    addNewCard: function(event) {
        if (!this.state.new_card.owner) {
            Messages.error('You must select an owner for new cards!');
        } else {
            AJAX.post(
                Link.get('addcard'),
                {card: this.state.new_card},
                function(response) {
                    this.setState({
                        cards: response.cards,
                        new_card: {
                            number: '',
                            owner: null,
                        },
                    });
                }.bind(this)
            );
        }
        event.preventDefault();
    },

    deleteExistingCard: function(card) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete Card',
            content: 'Are you sure you want to delete this card?',
            buttons: {
                Delete: {
                    btnClass: 'delete',
                    action: function() {
                        AJAX.post(
                            Link.get('removecard'),
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

    renderNumber: function(card) {
        return <Card number={card.number} />;
    },

    sortNumber: function(a, b) {
        return a.number.localeCompare(b.number);
    },

    renderOwner: function(card) {
        if (card.owner) {
            return (
                <span>{ card.owner }</span>
            );
        } else {
            return (
                <span className="placeholder">
                    anonymous account
                </span>
            );
        }
    },

    sortOwner: function(a, b) {
        var aown = a.owner ? a.owner : '';
        var bown = b.owner ? b.owner : '';
        return aown.localeCompare(bown);
    },

    renderEditButton: function(card) {
        return (
            <>
                <Edit
                    title="view/edit"
                    onClick={function(event) {
                        window.location=Link.get('viewuser', card.id);
                    }.bind(this)}
                />
                <Delete onClick={this.deleteExistingCard.bind(this, card.number)} />
            </>
        );
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    <h3>All cards</h3>
                    <Table
                        className="list cards"
                        columns={[
                            {
                                name: 'Card Number',
                                render: this.renderNumber,
                                sort: this.sortNumber,
                            },
                            {
                                name: 'Owner',
                                render: this.renderOwner,
                                sort: this.sortOwner,
                            },
                            {
                                name: '',
                                action: true,
                                render: this.renderEditButton,
                            },
                        ]}
                        rows={this.state.cards}
                        emptymessage="There are no cards in use on this network."
                    />
                </div>
                <div className="section">
                    <h3>Add Card</h3>
                    <form onSubmit={this.addNewCard}>
                        <table className="add cards">
                            <thead>
                                <th>Card Number</th>
                                <th>Owner</th>
                                <th></th>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>
                                        <input
                                            type="text"
                                            value={this.state.new_card.number}
                                            onChange={function(event) {
                                                var card = this.state.new_card;
                                                card.number = event.target.value;
                                                this.setState({new_card: card});
                                            }.bind(this)}
                                            name="card_number"
                                        />
                                    </td>
                                    <td>
                                        <SelectUser
                                            name="owner"
                                            value={ this.state.new_card.owner }
                                            usernames={ this.state.usernames }
                                            onChange={function(owner) {
                                                var card = this.state.new_card;
                                                card.owner = owner;
                                                this.setState({
                                                    new_card: card,
                                                });
                                            }.bind(this)}
                                        />
                                    </td>
                                    <td>
                                        <input type="submit" value="add card" />
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
