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
                            maxlength="10"
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
                                    } else if(c == ':'.charCodeAt(0)) {
                                       c = 0xFF1A;
                                    } else if(c == ';'.charCodeAt(0)) {
                                       c = 0xFF1B;
                                    } else if(c == '!'.charCodeAt(0)) {
                                       c = 0xFF01;
                                    } else if(c == '?'.charCodeAt(0)) {
                                       c = 0xFF1F;
                                    } else if(c == '+'.charCodeAt(0)) {
                                       c = 0xFF0B;
                                    } else if(c == '-'.charCodeAt(0)) {
                                       c = 0x2212;
                                    } else if(c == '#'.charCodeAt(0)) {
                                       c = 0xFF03;
                                    } else if(c == '_'.charCodeAt(0)) {
                                       c = 0xFF3F;
                                    } else if(c == '~'.charCodeAt(0)) {
                                       c = 0x301C;
                                    } else if(c == '*'.charCodeAt(0)) {
                                       c = 0xFF0A;
                                    } else if(c == '`'.charCodeAt(0)) {
                                       c = 0xFF40;
                                    } else if(c == '^'.charCodeAt(0)) {
                                       c = 0xFF3E;
                                    } else if(c == '<'.charCodeAt(0)) {
                                       c = 0xFF1C;
                                    } else if(c == '>'.charCodeAt(0)) {
                                       c = 0xFF1E;
                                    } else if(c == '('.charCodeAt(0)) {
                                       c = 0xFF08;
                                    } else if(c == ')'.charCodeAt(0)) {
                                       c = 0xFF09;
                                    } else if(c == '/'.charCodeAt(0)) {
                                       c = 0xFF0F;
                                    }
                                    value = value + String.fromCharCode(c);
                                }
                                var nameRegex = new RegExp(
                                    "^[" +
                                    "\uFF20-\uFF3A" + // widetext A-Z and @
                                    "\uFF40-\uFF5A" + // widetext a-z and `
                                    "\uFF10-\uFF19" + // widetext 0-9
                                    "\uFF0C\uFF0E\uFF3F\u0437\u2200\u2207" + // widetext ,._ and face symbols
                                    "\u3041-\u308D\u308F\u3092\u3093" + // hiragana
                                    "\u30A1-\u30ED\u30EF\u30F2\u30F3\u30FC" + // katakana
                                    "\u2605\u266A\uff01\uff1f\uff0b\u2212\u00d7\u00f7\uff03\u3002\u2267" + // allowed symbols
                                    "\u2266\u0434\u0398\u25a1\u76bf\uff1b\uff1a\u301c\uff0a\u00b4\uff3e" + // allowed symbols
                                    "\u309c\uff1c\uff1e\uff08\uff09\u8278\u30fb\uff0f\u309d\u03c9\u03b5" + // allowed symbols
                                    "]*$"
                                );
                                if (value.length <= 10 && nameRegex.test(value)) {
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

    render: function() {
        if (this.state.player[this.state.version]) {
            var player = this.state.player[this.state.version];
            return (
                <div>
                    <div className="section">
                        <h3>User Profile</h3>
                        {this.renderName(player)}
                    </div>
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
