/** @jsx React.DOM */

var Toggle = React.createClass({
    render: function() {
        return (
            <Button
                className="toggle"
                disabled={this.props.disabled}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title={this.props.title ? this.props.title : 'toggle'}
            />
        );
    },
});
