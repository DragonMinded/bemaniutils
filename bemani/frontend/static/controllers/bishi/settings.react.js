/*** @jsx React.DOM */

var valid_versions = Object.keys(window.versions);
var pagenav = new History(valid_versions);

var settings_view = createReactClass({

    sanitizeName: function(name) {
        if (name == 'なし') {
            return '';
        }
        return name;
    },

    getInitialState: function(props) {
        var profiles = Object.keys(window.player);
        var version = pagenav.getInitialState(profiles[profiles.length - 1]);
        return {
            player: window.player,
            profiles: profiles,
            version: version,
            new_name: this.sanitizeName(window.player[version].name),
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
                    new_name: this.sanitizeName(this.state.player[response.version].name),
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
                            maxlength="6"
                            size="6"
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
                                    } else if(c == ' '.charCodeAt(0)) {
                                        c = 0x3000;
                                    } else if(c == '~'.charCodeAt(0)) {
                                        c = 0x301C;
                                    } else if(c == '-'.charCodeAt(0)) {
                                        c = 0x2212;
                                    } else if(c == '!'.charCodeAt(0)) {
                                        c = 0xFF01;
                                    } else if(c == '#'.charCodeAt(0)) {
                                        c = 0xFF03;
                                    } else if(c == '$'.charCodeAt(0)) {
                                        c = 0xFF04;
                                    } else if(c == '%'.charCodeAt(0)) {
                                        c = 0xFF04;
                                    } else if(c == '&'.charCodeAt(0)) {
                                        c = 0xFF06;
                                    } else if(c == '('.charCodeAt(0)) {
                                        c = 0xFF08;
                                    } else if(c == ')'.charCodeAt(0)) {
                                        c = 0xFF09;
                                    } else if(c == '*'.charCodeAt(0)) {
                                        c = 0xFF0A;
                                    } else if(c == '+'.charCodeAt(0)) {
                                        c = 0xFF0B;
                                    } else if(c == '/'.charCodeAt(0)) {
                                        c = 0xFF0F;
                                    } else if(c == '<'.charCodeAt(0)) {
                                        c = 0xFF1C;
                                    } else if(c == '='.charCodeAt(0)) {
                                        c = 0xFF1D;
                                    } else if(c == '>'.charCodeAt(0)) {
                                        c = 0xFF1E;
                                    } else if(c == '?'.charCodeAt(0)) {
                                        c = 0xFF1F;
                                    }
                                    value = value + String.fromCharCode(c);
                                }
                                var nameRegex = new RegExp(
                                    "^[" +
                                    "\uFF20-\uFF3A" + // widetext A-Z, @
                                    "\uFF41-\uFF5A" + // widetext a-z (will be uppercased in backend)
                                    "\uFF10-\uFF19" + // widetext 0-9
                                    "\u3041-\u308D\u308F\u3092\u3093" + // hiragana
                                    "\u30A1-\u30ED\u30EF\u30F2\u30F3\u30FC" + // katakana
                                    "\u3000" + // widetext blank space
                                    "\u301C" + // widetext ~
                                    "\u30FB" + // widetext middot
                                    "\u30FC" + // widetext long dash
                                    "\u2212" + // widetext short dash
                                    "\u2605" + // widetext heavy star
                                    "\uFF01" + // widetext !
                                    "\uFF03" + // widetext #
                                    "\uFF04" + // widetext $
                                    "\uFF05" + // widetext %
                                    "\uFF06" + // widetext &
                                    "\uFF08" + // widetext (
                                    "\uFF09" + // widetext )
                                    "\uFF0A" + // widetext *
                                    "\uFF0B" + // widetext +
                                    "\uFF0F" + // widetext /
                                    "\uFF1C" + // widetext <
                                    "\uFF1D" + // widetext =
                                    "\uFF1E" + // widetext >
                                    "\uFF1F" + // widetext ?
                                    "\uFFE5" + // widetext Yen symbol
                                    "]*$"
                                );
                                if (value.length <= 6 && nameRegex.test(value)) {
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
                                    new_name: this.sanitizeName(this.state.player[this.state.version].name),
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
                                            new_name: this.sanitizeName(this.state.player[version].name),
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
