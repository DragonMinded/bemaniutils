/** @jsx React.DOM */

var Prev = createReactClass({
    render: function() {
        return (
            <Nav
                disabled={this.props.disabled}
                style={this.props.style}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title="prev"
            />
        );
    },

    handler: function(e) {
        if (e.which == 37) {
            this.props.onClick(e);
            e.preventDefault();
        }
    },

    componentDidMount: function() {
        this.boundhandler = this.handler.bind(this);
        $(document).keydown(this.boundhandler);
    },

    componentWillUnmount: function() {
        if (this.boundhandler) {
            $(document).unbind('keydown', this.boundhandler);
            this.boundhandler = null;
        }
    }
});
