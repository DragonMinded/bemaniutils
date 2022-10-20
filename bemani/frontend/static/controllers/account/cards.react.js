/*** @jsx React.DOM */

var card_management = createReactClass({
    getInitialState: function(props) {
        return {
            cards: window.cards,
            newCard: '',
        };
    },

    componentDidMount: function() {
        this.refreshCardList();
    },

    addNewCard: function(event) {
        AJAX.post(
            Link.get('addcard'),
            {card: this.state.newCard},
            function(response) {
                this.setState({
                    cards: response.cards,
                    newCard: '',
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    deleteExistingCard: function(card) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete Card',
            content: 'Are you sure you want to delete this card from your account?',
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
                                    newCard: '',
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

    refreshCardList: function() {
        AJAX.get(
            Link.get('listcards'),
            function(response) {
                this.setState({
                    cards: response.cards,
                });
                setTimeout(this.refreshCardList, 2500);
            }.bind(this)
        );
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    <h3>Your Cards</h3>
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
                            value={this.state.newCard}
                            onChange={function(event) {
                                this.setState({newCard: event.target.value});
                            }.bind(this)}
                            name="card_number"
                        />
                        <input type="submit" value="add card" />
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
