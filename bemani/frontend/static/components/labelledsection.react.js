/** @jsx React.DOM */

var LabelledSection = createReactClass({
    render: function() {
        return (
            <div
                className={classNames(
                    "labelledsection",
                    {"vertical": this.props.vertical, "horizontal": !this.props.vertical},
                    this.props.className
                )}
            >
                <div className="label">{this.props.label}</div>
                <div className="content">{this.props.children}</div>
            </div>
        );
    },
});
