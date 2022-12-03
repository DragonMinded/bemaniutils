/** @jsx React.DOM */

var Delete = createReactClass({
    render: function() {
        return (
            <Button
                className="delete"
                style={this.props.style}
                disabled={this.props.disabled}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title={this.props.title ? this.props.title : 'delete'}
            />
        );
    },
});
