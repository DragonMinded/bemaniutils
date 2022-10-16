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
                            maxlength="8"
                            size="16"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_name}
                            onChange={function(event) {
                                var rawvalue = event.target.value;
                                if (this.state.version <= 3) {
                                    // Only allow uppercase, so convert to be helpful
                                    rawvalue = rawvalue.toUpperCase();
                                }
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
                                    } else if(c == '.'.charCodeAt(0)) {
                                        c = 0xFF0E;
                                    } else if(c == '-'.charCodeAt(0)) {
                                        c = 0x2212;
                                    } else if(c == '_'.charCodeAt(0)) {
                                        c = 0xFF3F;
                                    } else if(c == '&'.charCodeAt(0)) {
                                        c = 0xFF06;
                                    } else if(c == '!'.charCodeAt(0)) {
                                        c = 0xFF01;
                                    } else if(c == '?'.charCodeAt(0)) {
                                        c = 0xFF1F;
                                    } else if(c == '/'.charCodeAt(0)) {
                                        c = 0xFF0F;
                                    } else if(c == '*'.charCodeAt(0)) {
                                        c = 0xFF0A;
                                    } else if(c == '#'.charCodeAt(0)) {
                                        c = 0xFF03;
                                    } else if(c == '@'.charCodeAt(0)) {
                                        c = 0xFF20;
                                    } else if(c == '('.charCodeAt(0)) {
                                        c = 0xFF08;
                                    } else if(c == ')'.charCodeAt(0)) {
                                        c = 0xFF09;
                                    } else if(c == '^'.charCodeAt(0)) {
                                        c = 0xFF3E;
                                    } else if(c == '%'.charCodeAt(0)) {
                                        c = 0xFF05;
                                    } else if(c == ' '.charCodeAt(0)) {
                                        c = 0x3000;
                                    }
                                    value = value + String.fromCharCode(c);
                                }
                                var nameRegex;
                                if (this.state.version <= 3) {
                                    nameRegex = new RegExp(
                                        "^[" +
                                        "\uFF21-\uFF3A" +
                                        "\uFF10-\uFF19" +
                                        "\uFF0E\u2212\uFF3F\u30FB" +
                                        "\uFF06\uFF01\uFF1F\uFF0F" +
                                        "\uFF0A\uFF03\u266D\u2605" +
                                        "\uFF20\u266A\u2193\u2191" +
                                        "\u2192\u2190\uFF08\uFF09" +
                                        "\u221E\u25C6\u25CF\u25BC" +
                                        "\uFFE5\uFF3E\u2200\uFF05" +
                                        "\u3000" +
                                        "]*$"
                                    );
                                } else {
                                    nameRegex = new RegExp(
                                        "^[" +
                                        "\uFF21-\uFF3A" +
                                        "\uFF41-\uFF5A" +
                                        "\uFF10-\uFF19" +
                                        "\uFF0E\u2212\uFF3F\u30FB" +
                                        "\uFF06\uFF01\uFF1F\uFF0F" +
                                        "\uFF0A\uFF03\u266D\u2605" +
                                        "\uFF20\u266A\u2193\u2191" +
                                        "\u2192\u2190\uFF08\uFF09" +
                                        "\u221E\u25C6\u25CF\u25BC" +
                                        "\uFFE5\uFF3E\u2200\uFF05" +
                                        "\u3000" +
                                        "]*$"
                                    );
                                }
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
