/** @jsx React.DOM */

var Button = React.createClass({
    render: function() {
        return (
            <button
                className={this.props.className}
                style={this.props.style}
                disabled={this.props.disabled}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
            >
                {this.props.title}
            </button>
        );
    },
});
