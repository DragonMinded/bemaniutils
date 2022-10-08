/** @jsx React.DOM */

var LabelledSection = createReactClass({
    render: function() {
        var classname = "labelledsection"
        if (this.props.vertical) {
            classname = classname + " vertical";
        } else {
            classname = classname + " horizontal";
        }
        if (this.props.className) {
            classname = classname + " " + this.props.className;
        }
        return (
            <div
                className={classname}
            >
                <div className="label">{this.props.label}</div>
                <div className="content">{this.props.children}</div>
            </div>
        );
    },
});
