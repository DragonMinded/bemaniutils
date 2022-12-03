/** @jsx React.DOM */

var Add = createReactClass({
    render: function() {
        return (
            <Button
                className="add"
                style={this.props.style}
                disabled={this.props.disabled}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title={this.props.title ? this.props.title : 'add'}
            />
        );
    },
});
