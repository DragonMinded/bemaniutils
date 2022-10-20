/** @jsx React.DOM */

var Rival = createReactClass({
    render: function() {
        if (this.props.player.remote) {
            return <span>{ this.props.player.name }</span>;
        } else {
            return <a href={Link.get('player', this.props.userid)}>{ this.props.player.name }</a>;
        }
    },
});
