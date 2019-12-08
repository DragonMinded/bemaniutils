/** @jsx React.DOM */

var Checkbox = React.createClass({
    render: function() {
        return (
            <span className={this.props.className} onClick={this.props.onClick}>
                {this.props.checked ?
                    <span className="checkbox">&#9745;</span> :
                    <span className="checkbox">&#9744;</span>
                }
            </span>
        );
    },
});
