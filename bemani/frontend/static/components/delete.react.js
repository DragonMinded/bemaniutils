/** @jsx React.DOM */

var Delete = React.createClass({
    render: function() {
        return (
            <Button
                className="delete"
                disabled={this.props.disabled}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title={this.props.title ? this.props.title : 'delete'}
            />
        );
    },
});
