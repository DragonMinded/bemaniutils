/** @jsx React.DOM */

var SelectInt = createReactClass({
    __renderChoices: function() {
        if (this.props.choices instanceof Array) {
            // Given to us as an array, the index of the value is the selected value
            return (
                this.props.choices.map(function(choice, index) {
                    if (choice == null) { return null; }
                    return <option value={index}>{ choice }</option>;
                }.bind(this))
            );
        } else {
            // Assume given as an object, the keys are the values and the values are the displays
            return (
                Object.keys(this.props.choices).map(function(choice) {
                    return <option value={choice}>{ this.props.choices[choice] }</option>;
                }.bind(this))
            );
        }
    },

    render: function() {
        return (
            <select
                name={this.props.name}
                disabled={this.props.disabled}
                value={this.props.value ? this.props.value : 0}
                onChange={function(event) {
                    var integer = parseInt(event.target.value);
                    if (this.props.onChange) {
                        this.props.onChange(integer);
                    }
                }.bind(this)}
            >
                {this.__renderChoices()}
            </select>
        );
    },
});
