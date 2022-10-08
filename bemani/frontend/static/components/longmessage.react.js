/** @jsx React.DOM */

var LongMessage = createReactClass({
    getInitialState: function(props) {
        return {
            expanded: false,
        };
    },

    render: function() {
        var length = this.props.length ? this.props.length : 50;
        var text = this.props.children;
        if (text.length > length) {
            if (this.state.expanded) {
                return (
                    <div className="longmessage">
                        <pre>{text}</pre>
                        <button
                            className="viewmore"
                            onClick={function(event) {
                                this.setState({expanded: false});
                            }.bind(this)}
                        >view less</button>
                    </div>
                );
            } else {
                return (
                    <div className="longmessage">
                        <pre>{text.substring(0, length)}...</pre>
                        <button
                            className="viewmore"
                            onClick={function(event) {
                                this.setState({expanded: true});
                            }.bind(this)}
                        >view more</button>
                    </div>
                );
            }
        } else {
            return <div className="longmessage"><pre>{text}</pre></div>;
        }
    },
});
