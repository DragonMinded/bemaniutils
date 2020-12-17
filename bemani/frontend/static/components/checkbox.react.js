/** @jsx React.DOM */

var Checkbox = React.createClass({
    render: function() {
        return (
            <span className={this.props.className} onClick={this.props.onClick}>
                {this.props.checked ?
                    <span className="checkbox">{ "\u2611" }</span> :
                    <span className="checkbox">{ "\u2610" }</span>
                }
            </span>
        );
    },
});
