/*** @jsx React.DOM */

var dancemates_view = createReactClass({

    getInitialState: function(props) {
        return {
            name: window.name,
            version: window.version,
            dancemates: window.dancemates,
            profiles: window.profiles,
        };
    },

    componentDidMount: function() {
        this.refreshDanceMates();
    },

    refreshDanceMates: function() {
        AJAX.get(
            Link.get('refresh'),
            function(response) {
                this.setState({
                    name: response.name,
                    version: response.version,
                    dancemates: response.dancemates,
                    profiles: response.profiles,
                });
                setTimeout(this.refreshDanceMates, 5000);
            }.bind(this)
        );
    },

    renderDanceMates: function(player) {
        return(
            <Table
                className='list dancemates'
                columns={[
                    {
                        name: 'Name',
                        render: function(entry) {
                            return this.state.profiles[entry.userid][this.state.version].name;
                        }.bind(this),
                        sort: function(aid, bid) {
                            var a = this.state.profiles[aid.userid][this.state.version].name;
                            var b = this.state.profiles[bid.userid][this.state.version].name;
                            return a.localeCompare(b);
                        }.bind(this),
                    },
                    {
                        name: 'Last Played With',
                        render: function(entry) {
                            return <Timestamp className={"dancemate"} timestamp={entry.last_played}/>;
                        },
                        sort: function(aid, bid) {
                            return aid.last_played - bid.last_played;
                        }.bind(this),
                    },
                ]}
                defaultsort='Name'
                rows={this.state.dancemates}
                paginate={10}
            />
        );
    },

    render: function() {
        return (
            <div>
                <section>
                    <h3>{this.state.name}'s Dance Mates</h3>
                    <p>
                        {this.renderDanceMates()}
                    </p>
                </section>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(dancemates_view, null),
    document.getElementById('content')
);
