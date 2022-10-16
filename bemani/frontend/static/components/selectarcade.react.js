/** @jsx React.DOM */

var SelectArcade = createReactClass({
    render: function() {
        return (
            <select
                name={this.props.name}
                disabled={this.props.disabled}
                value={this.props.value ? this.props.value : "__NOTHING_VALUE__"}
                onChange={function(event) {
                    var owner = event.target.value;
                    if (owner == "__NOTHING_VALUE__") {
                        owner = null;
                    }
                    if (this.props.onChange) {
                        this.props.onChange(owner);
                    }
                }.bind(this)}
            >
                <option className="placeholder" value="__NOTHING_VALUE__">no arcade</option>
                {Object.keys(this.props.arcades).map(function(key, index) {
                    return <option value={key}>{ this.props.arcades[key] }</option>;
                }.bind(this))}
            </select>
        );
    },
});
