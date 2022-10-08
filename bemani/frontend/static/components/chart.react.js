/** @jsx React.DOM */

var Graph = createReactClass({
    componentDidMount: function() {
        var config = {
            type: this.props.type,
            data: this.props.data,
            options: this.props.options || {},
        };
        this.chart_instance = new Chart(this.element, config);
    },

    componentWillUnmount: function() {
        this.chart_instance.destroy();
    },

    componentWillReceiveProps: function(nextProps) {
        const dataChanged = this.props.data !== nextProps.data;
        const optionsChanged = this.props.options !== nextProps.options;
        if (optionsChanged || dataChanged) {
            this.chart_instance.destroy();
            var config = {
                type: this.props.type,
                data: nextProps.data,
                options: nextProps.options || {},
            };
            this.chart_instance = new Chart(this.element, config);
        }
    },

    ref: function(element) {
        this.element = element;
    },

    render: function() {
        return (
            <canvas
                ref={this.ref}
                height={this.props.height}
                width={this.props.width}
            />
        );
    },

});

var LineGraph = createReactClass({

    render: function() {
        return (
            <Graph
                type="line"
                data={this.props.data}
                options={this.props.options}
                width={this.props.width}
                height={this.props.height}
            />
        );
    },
});

var RadarGraph = createReactClass({

    render: function() {
        return (
            <Graph
                type="radar"
                data={this.props.data}
                options={this.props.options}
                width={this.props.width}
                height={this.props.height}
            />
        );
    },
});
