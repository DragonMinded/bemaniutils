/** @jsx React.DOM */

var Nav = createReactClass({
    render: function() {
        var title = (
           <>
                {this.props.title}
                {this.props.showAlert ?
                    <span className="alert">{ "\u26a0" }</span> :
                    null
                }
            </>
        );
        return (
            <Button
                className={classNames("nav", {"active": this.props.active}, this.props.title)}
                disabled={this.props.disabled}
                style={this.props.style}
                onClick={function(event) {
                    this.props.onClick(event);
                }.bind(this)}
                title={title}
            />
        );
    },
});
