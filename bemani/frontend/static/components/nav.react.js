/** @jsx React.DOM */

var Nav = React.createClass({
    render: function() {
        var cls = 'nav';
        if (this.props.active) {
            cls += ' active';
        }
        cls += " " + this.props.title;

        var title = (
           <span>
                {this.props.title}
                {this.props.showAlert ?
                    <span className="alert">{ "\u26a0" }</span> :
                    null
                }
            </span>
        );
        return (
            <Button
                className={cls}
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
