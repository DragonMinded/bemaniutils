/** @jsx React.DOM */

var SelectUser = createReactClass({
    render: function() {
        return (
            <select
                name={this.props.name}
                disabled={this.props.disabled}
                value={this.props.value ? this.props.value : "__NOBODY_VALUE__"}
                onChange={function(event) {
                    var owner = event.target.value;
                    if (owner == "__NOBODY_VALUE__") {
                        owner = null;
                    }
                    if (this.props.onChange) {
                        this.props.onChange(owner);
                    }
                }.bind(this)}
            >
                <option className="placeholder" value="__NOBODY_VALUE__">nobody</option>
                {this.props.usernames.map(function(username) {
                    return <option value={username}>{ username }</option>;
                }.bind(this))}
            </select>
        );
    },
});
