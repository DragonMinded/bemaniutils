/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var settings_view = createReactClass({

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        var version = pagenav.getInitialState(profiles[profiles.length - 1]);
        return {
            player: window.player,
            profiles: profiles,
            version: version,
            title_changed: {},
            title_saving: {},
            title_saved: {},
            new_name: window.player[version].name,
            editing_name: false,
        };
    },

    componentDidMount: function() {
        pagenav.onChange(function(version) {
            this.setState({version: version});
        }.bind(this));
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    setTitleChanged: function (val) {
        this.state.title_changed[this.state.version] = val;
        return this.state.title_changed;
    },

    setTitlesSaving: function (val) {
        this.state.title_saving[this.state.version] = val;
        return this.state.title_saving;
    },

    setTitlesSaved: function (val) {
        this.state.title_saved[this.state.version] = val;
        return this.state.title_saved;
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

    saveTitle: function (event) {
        this.setState({
            title_saving: this.setTitlesSaving(true),
            title_saved: this.setTitlesSaved(false),
        });
        AJAX.post(
            Link.get('updatetitlesettings'),
            {
                version: this.state.version,
                title: this.state.player[this.state.version].title,
            },
            function (response) {
                var player = this.state.player;
                player[response.version].title = response.title;
                this.setState({
                    player: player,
                    title_saving: this.setTitlesSaving(false),
                    title_saved: this.setTitlesSaved(true),
                    title_changed: this.setTitleChanged(false),
                });
            }.bind(this)
        );
        event.preventDefault();
    },    

    renderName: function(player) {
        return (
            <LabelledSection vertical={true} label="Name">{
                !this.state.editing_name ?
                    <>
                        <span>{player.name}</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_name: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.saveName}>
                        <input
                            type="text"
                            className="inline"
                            maxlength="8"
                            size="12"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_name}
                            onChange={function(event) {
                                var rawvalue = event.target.value;
                                var value = "";
                                // Nasty conversion to change typing into wide text
                                for (var i = 0; i < rawvalue.length; i++) {
                                    var c = rawvalue.charCodeAt(i);
                                    if (c >= '0'.charCodeAt(0) && c <= '9'.charCodeAt(0)) {
                                        c = 0xFF10 + (c - '0'.charCodeAt(0));
                                    } else if(c >= 'A'.charCodeAt(0) && c <= 'Z'.charCodeAt(0)) {
                                        c = 0xFF21 + (c - 'A'.charCodeAt(0));
                                    } else if(c >= 'a'.charCodeAt(0) && c <= 'z'.charCodeAt(0)) {
                                        c = 0xFF41 + (c - 'a'.charCodeAt(0));
                                    } else if(c == '@'.charCodeAt(0)) {
                                        c = 0xFF20;
                                    } else if(c == ','.charCodeAt(0)) {
                                        c = 0xFF0C;
                                    } else if(c == '.'.charCodeAt(0)) {
                                        c = 0xFF0E;
                                    } else if(c == '_'.charCodeAt(0)) {
                                       c = 0xFF3F;
                                    }
                                    value = value + String.fromCharCode(c);
                                }
                                var nameRegex = new RegExp(
                                    "^[" +
                                    "\uFF20-\uFF3A" + // widetext A-Z and @
                                    "\uFF41-\uFF5A" + // widetext a-z
                                    "\uFF10-\uFF19" + // widetext 0-9
                                    "\uFF0C\uFF0E\uFF3F" + // widetext ,._-!
                                    "\u3041-\u308D\u308F\u3092\u3093" + // hiragana
                                    "\u30A1-\u30ED\u30EF\u30F2\u30F3\u30FC" + // katakana
                                    "\u4E00-\u9FFF" + //triditional chinese and simplified chinese
                                    "]*$"
                                );
                                if (value.length <= 8 && nameRegex.test(value)) {
                                    this.setState({new_name: value});
                                }
                            }.bind(this)}
                            name="name"
                        />
                        <input
                            type="submit"
                            value="save"
                        />
                        <input
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

    renderTitle: function() {
        return (
            <section>
                <div>
                    <h3>Title Name
                        <span ref={this.__hoverBoxRef}>
                            <span style={{marginLeft: '0.5em', textDecoration: 'underline', fontSize: '0.9em'}}>Warning: Please do not enter any language other than Japanese or English.</span>
                        </span>
                    </h3>
                    <form onSubmit={this.saveTitle}>
                        <div className="fields">
                            {[1].map(function (msgIndex) {
                                return (
                                    <div className="field">
                                        <input
                                            type="text"
                                            placeholder={"Title Name" + msgIndex.toString()}
                                            value={this.state.player[this.state.version].title}
                                            onChange={function (e) {
                                                const player = this.state.player;
                                                player[this.state.version].title = e.target.value;
                                                this.setState({
                                                    player: player,
                                                    title_changed: this.setTitleChanged(true),
                                                });
                                            }.bind(this)}
                                        />
                                    </div>
                                )
                            }.bind(this))}
                            <div className="field">
                            <input type="submit" value="Save" disabled={!this.state.title_changed[this.state.version]} />
                                { this.state.title_saving[this.state.version] && <img className="loading" src={Link.get('static', window.assets + 'loading-16.gif')} />}
                                { this.state.title_saved[this.state.version] && <span>{ "\u2713" }</span>}
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
            return (
                <div>
                    <div className="section gitadora-nav">
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
                        this.renderTitle(player)
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
