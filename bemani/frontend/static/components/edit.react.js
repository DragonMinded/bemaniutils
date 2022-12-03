/** @jsx React.DOM */

var Edit = createReactClass({
    render: function() {
        return (
            <Button
                className="edit"
                style={this.props.style}
                disabled={this.props.disabled}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title={this.props.title ? this.props.title : 'update'}
            />
        );
    },
});
