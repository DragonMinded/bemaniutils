/** @jsx React.DOM */

var Slider = createReactClass({
    render: function() {
        return (
            <div
                className={classNames("slider", this.props.value ? "on" : "off", this.props.className)}
                onClick={function(event) {
                    event.preventDefault();
                    event.stopPropagation();
                    if (this.props.onChange) {
                        this.props.onChange(!this.props.value);
                    }
                }.bind(this)}
            >{ this.props.value ?
                <>
                    <span className="ball on"></span>
                    <span className="label on">{this.props.on}</span>
                </> :
                <>
                    <span className="label off">{this.props.off}</span>
                    <span className="ball off"></span>
                </>
            }</div>
        );
    },
});
