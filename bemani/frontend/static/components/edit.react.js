/** @jsx React.DOM */

var Edit = React.createClass({
    render: function() {
        return (
            <Button
                className="edit"
                disabled={this.props.disabled}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title={this.props.title ? this.props.title : 'update'}
            />
        );
    },
});
