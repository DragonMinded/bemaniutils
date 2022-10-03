/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var valid_emblem_options = [
    'background',
    'main',
    'ornament',
    'effect',
    'speech_bubble',
]

var emblem_option_names = {
    'main': 'Main',
    'background': 'Background',
    'ornament': 'Ornament',
    'effect': 'Effect',
    'speech_bubble': 'Speech Bubble',
}

var settings_view = React.createClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        var version = pagenav.getInitialState(profiles[profiles.length - 1]);
        return {
            player: window.player,
            profiles: profiles,
            version: version,
            new_name: window.player[version].name,
            editing_name: false,
            emblem_changed: {},
            emblem_saving: {},
            emblem_saved: {},
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(version) {
            this.setState({
                version: version,
            });
        }.bind(this));
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    setEmblemChanged: function(val) {
        this.state.emblem_changed[this.state.version] = val;
        return this.state.emblem_changed
    },

    setEmblemSaving: function(val) {
        this.state.emblem_saving[this.state.version] = val;
        return this.state.emblem_saving
    },

    setEmblemSaved: function(val) {
        this.state.emblem_saved[this.state.version] = val;
        return this.state.emblem_saved
    },

    saveEmblem: function(event) {
        this.setState({ emblem_saving: this.setEmblemSaving(true), emblem_saved: this.setEmblemSaved(false) })
        AJAX.post(
            Link.get('updateemblem'),
            {
                version: this.state.version,
                emblem: this.state.player[this.state.version].emblem,
            },
            function(response) {
                var player = this.state.player
                player[response.version].emblem = response.emblem
                this.setState({
                    player: player,
                    emblem_saving: this.setEmblemSaving(false),
                    emblem_saved: this.setEmblemSaved(true),
                    emblem_changed: this.setEmblemChanged(false),
                })
            }.bind(this)
        )
    },

    saveName: function(event) {
        AJAX.post(
            Link.get('updatename'),
            {
                version: this.state.version,
                name: this.state.new_name,
            },
            function(response) {
                var player = this.state.player;
                player[response.version].name = response.name;
                this.setState({
                    player: player,
                    new_name: this.state.player[response.version].name,
                    editing_name: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    renderName: function(player) {
        return (
            <LabelledSection vertical={true} label="Username">{
                !this.state.editing_name ?
                    <span>
                        <p>
                            {player.name}
                            <br/>
                            <Edit
                                onClick={function(event) {
                                    this.setState({editing_name: true});
                                }.bind(this)}
                            />
                        </p>
                    </span> :
                    <form className="inline" onSubmit={this.saveName}>
                        <input
                            type="text"
                            className="inline"
                            maxlength="8"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            size="8"
                            value={this.state.new_name}
                            onChange={function(event) {
                                var value = event.target.value.toUpperCase();
                                var nameRegex = /^[ -&\\.\\*A-Z0-9]*$/;
                                if (value.length <= 8 && nameRegex.test(value)) {
                                    this.setState({new_name: value});
                                }
                            }.bind(this)}
                            name="name"
                        />
                        <br/>
                        <input
                            className="small"
                            type="submit"
                            value="save"
                        />
                        <input
                            className="small"
                            type="button"
                            value="cancel"
                            onClick={function(event) {
                                this.setState({
                                    new_name: this.state.player[this.state.version].name,
                                    editing_name: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    renderEmblem: function(player) {
        return (
            <section>
                <div className="inner">
                    <h3>Emblem</h3>
                    <div style={{position: 'relative', width: '256px', height: '256px', left: '0', right: '0', margin: 'auto'}}>
                    {
                        valid_emblem_options.map(function(emblem_option) {
                            var player = this.state.player[this.state.version]
                            var src = `/static/emblems/${player.emblem[emblem_option]}.png`
                            const divStyle = {
                                position: 'absolute',
                            }
                            const imageStyle = {
                                width: '256px',
                                height: '256px',
                            }
                            return (
                                <div style={divStyle}>
                                    <img style={imageStyle} src={src}/>
                                </div>
                            )
                        }.bind(this))
                    }
                    </div>
                    <form className="inline">
                        <div className="fields">
                            {
                                valid_emblem_options.map(function(emblem_option) {
                                    var player = this.state.player[this.state.version]
                                    var layer = valid_emblem_options.indexOf(emblem_option) + 1
                                    var items = window.emblems[this.state.version].filter(function (emblem) {
                                        return emblem.layer == layer
                                    });
                                    var results = {};
                                    items
                                        .map(function(item) { return { 'index': item.index, 'name': `${item.name} (★${item.rarity})` } })
                                        .forEach (value => results[value.index] = value.name);
                                    if (layer != 2) {
                                        results[0] = "None"
                                    }
                                    return(
                                        <div className="field">
                                            <b>{emblem_option_names[emblem_option]}</b>
                                            <br/>
                                            <SelectInt
                                                name={emblem_option}
                                                value={player.emblem[emblem_option]}
                                                choices={results}
                                                onChange={function(choice) {
                                                    var player = this.state.player;
                                                    player[this.state.version].emblem[emblem_option] = choice;
                                                    this.setState({
                                                        player: player,
                                                        emblem_changed: this.setEmblemChanged(true),
                                                    })
                                                }.bind(this)}
                                            />
                                        </div>
                                    )
                                }.bind(this))
                            }
                            <div className="field">
                                <input
                                    type="submit"
                                    value="save"
                                    disabled={!this.state.emblem_changed[this.state.version]}
                                    onClick={function(event) {
                                        this.saveEmblem(event);
                                    }.bind(this)}
                                />
                                { this.state.emblem_saving[this.state.version] ?
                                    <img className="loading" src={Link.get('static', 'loading-16.gif')} /> :
                                    null
                                }
                                { this.state.emblem_saved[this.state.version] ?
                                    <span>&#x2713;</span> :
                                    null
                                }
                            </div>
                        </div>
                    </form>
                </div>
            </section>
        )
    },

    render: function() {
        if (this.state.player[this.state.version]) {
            var player = this.state.player[this.state.version];
            var filteredVersion = Object.values(this.state.profiles).map(function(version) {
                return Object.values(window.versions)[version-1]
            });
            var item = Object.keys(window.versions).map(function(k){
                return window.versions[k]
            })
            return (
                <div>
                    <div className="section">
                        {this.state.profiles.map(function(version) {
                            return (
                                <Nav
                                    title={window.versions[version]}
                                    active={this.state.version == version}
                                    onClick={function(event) {
                                        if (this.state.editing_name) { return; }
                                        if (this.state.version == version) { return; }
                                        this.setState({
                                            version: version,
                                            new_name: this.state.player[version].name,
                                        });
                                        pagenav.navigate(version);
                                    }.bind(this)}
                                />
                            );
                        }.bind(this))}
                    </div>
                    <div className="section">
                        <h3>User Profile</h3>
                        {this.renderName(player)}
                    </div>
                    {
                        this.state.version > 9 ? this.renderEmblem(player) : null
                    }
                </div>
            );
        } else {
            return (
                <div>
                    <div className="section">
                        You have no profile for {window.versions[this.state.version]}!
                    </div>
                    <div className="section">
                        {this.state.profiles.map(function(version) {
                            return (
                                <Nav
                                    title={window.versions[version]}
                                    active={this.state.version == version}
                                    onClick={function(event) {
                                        if (this.state.version == version) { return; }
                                        this.setState({
                                            version: version,
                                        });
                                        pagenav.navigate(version);
                                    }.bind(this)}
                                />
                            );
                        }.bind(this))}
                    </div>
                </div>
            );
        }
    },
});

ReactDOM.render(
    React.createElement(settings_view, null),
    document.getElementById('content')
);
