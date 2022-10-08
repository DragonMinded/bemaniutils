/*** @jsx React.DOM */

var home = createReactClass({
    getInitialState: function(props) {
        return {
            news: window.news,
        };
    },

    render: function() {
        return (
            <div>{
                this.state.news.map(function(entry) {
                    return (
                        <div className="section">
                            <h3>{ entry.title }</h3>
                            <Timestamp timestamp={entry.timestamp} />
                            <div dangerouslySetInnerHTML={ {__html: entry.body} }></div>
                        </div>
                    );
                }.bind(this))
            }</div>
        );
    },
});

ReactDOM.render(
    React.createElement(home, null),
    document.getElementById('content')
);
