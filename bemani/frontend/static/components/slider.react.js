/** @jsx React.DOM */

var Slider = createReactClass({
    key: function(e) {
        if (e.keyCode == 32) {
            // Toggle on space.
            if (this.props.onChange) {
                this.props.onChange(!this.props.value);
            }
        } else if (e.keyCode == 39) {
            // Slide with cursor keys.
            if (this.props.onChange && this.props.value) {
                this.props.onChange(!this.props.value);
            }
        } else if (e.keyCode == 37) {
            // Slide with cursor keys.
            if (this.props.onChange && !this.props.value) {
                this.props.onChange(!this.props.value);
            }
        } else {
            // Don't handle, so don't hit the default prevent below.
            return;
        }
        e.preventDefault();
        e.stopPropagation();
    },

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
                tabindex={0}
                onKeyDown={this.key}
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
