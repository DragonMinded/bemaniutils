/** @jsx React.DOM */

var Card = React.createClass({
    render: function() {
        return (
            <div className="card">{
                this.props.number.substring(0, 4) +
                ' ' +
                this.props.number.substring(4, 8) +
                ' ' +
                this.props.number.substring(8, 12) +
                ' ' +
                this.props.number.substring(12, 16)
            }</div>
        );
    },
});
