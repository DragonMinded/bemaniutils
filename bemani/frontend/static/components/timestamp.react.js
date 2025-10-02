/** @jsx React.DOM */

var Timestamp = createReactClass({
    render: function() {
        if (this.props.timestamp <= 0) {
            return <div className="timestamp">N/A</div>;
        }

        var t = new Date(this.props.timestamp * 1000);
        var formatted = t.format('Y/m/d @ g:i:s a');
        return (
            <div className={this.props.className || "timestamp"}>{ formatted }</div>
        );
    },
});
