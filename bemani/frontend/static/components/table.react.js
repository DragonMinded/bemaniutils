/** @jsx React.DOM */

var Table = React.createClass({
    getInitialState: function(props) {
        var sortCol = -1;
        var sortDir = -1;
        this.props.columns.map(function(column, index) {
            if (column.sort) {
                if ((this.props.defaultsort && column.name == this.props.defaultsort) || sortCol == -1) {
                    sortCol = index;
                    sortDir = column.reverse ? 1 : -1;
                }
            }
        }.bind(this));

        return {
            offset: 0,
            sortCol: sortCol,
            sortDir: sortDir,
            key: Math.floor(Math.random() * 573573573),
        };
    },

    colLength: function() {
        var len = 0;
        this.props.columns.map(function(column) {
            if (column.hidden) { return; }
            len = len + 1;
        }.bind(this));
        return len;
    },

    sort: function() {
        if (this.state.sortCol < 0 || this.state.sortCol >= this.colLength()) {
            return this.props.rows;
        } else if (this.props.rows.length == 0) {
            return [];
        } else {
            return this.props.rows.concat().sort(function(a, b) {
                var val = this.props.columns[this.state.sortCol].sort(a, b);
                if (this.state.sortDir < 0) {
                    return val;
                } else {
                    return -val;
                }
            }.bind(this));
        }
    },

    render: function() {
        if (this.props.rows.length == 0) {
            var msg = this.props.emptymessage ? this.props.emptymessage : 'There is no data to display.';
            return <span className="placeholder">{msg}</span>;
        }

        return (
            <table className={this.props.className} key={this.props.key ? this.props.key : this.state.key}>
                <thead>
                    <tr>
                        {this.props.columns.map(function(column, index) {
                            if (column.hidden) { return null; }

                            var sort = <span />;
                            var click = null;
                            if (index == this.state.sortCol) {
                                if (this.state.sortDir < 0) {
                                    sort = <span className="sort">{ " \u2191" }</span>;
                                    click = function() {
                                        this.setState({sortDir: 1});
                                    }.bind(this);
                                } else {
                                    sort = <span className="sort">{ " \u2193" }</span>;
                                    click = function() {
                                        this.setState({sortDir: -1});
                                    }.bind(this);
                                }
                            } else {
                                if (column.sort) {
                                    sort = <span className="sort">{ " \u2195" }</span>;
                                    click = function() {
                                        this.setState({sortCol: index, sortDir: column.reverse ? 1 : -1});
                                    }.bind(this);
                                }
                            }

                            if (column.action) {
                                return (
                                    <th className="action" onClick={click}>{column.name}{sort}</th>
                                );
                            } else {
                                return (
                                    <th onClick={click}>{column.name}{sort}</th>
                                );
                            }
                        }.bind(this))}
                    </tr>
                </thead>
                <tbody>
                    {this.sort().map(function(row, index) {
                        if (this.props.paginate) {
                            if (index < this.state.offset || index >= this.state.offset + this.props.paginate) {
                                return null;
                            }
                        }

                        return (
                            <tr>
                                {this.props.columns.map(function(column) {
                                    if (column.hidden) { return null; }

                                    return (
                                        <td className={column.action ? "edit" : column.className}>{
                                            column.render(row)
                                        }</td>
                                    );
                                }.bind(this))}
                            </tr>
                        );
                    }.bind(this))}
                </tbody>
                { this.props.paginate ?
                    <tfoot>
                        <tr>
                            <td colSpan={this.colLength()}>
                                { this.state.offset > 0 ?
                                    <Prev onClick={function(event) {
                                         var page = this.state.offset - this.props.paginate;
                                         if (page < 0) { page = 0; }
                                         this.setState({offset: page});
                                    }.bind(this)}/> : null
                                }
                                { (this.state.offset + this.props.paginate) < this.props.rows.length ?
                                    <Next style={ {float: 'right'} } onClick={function(event) {
                                         var page = this.state.offset + this.props.paginate;
                                         if (page >= this.props.rows.length) { return }
                                         this.setState({offset: page});
                                    }.bind(this)}/> :
                                    this.props.loading ?
                                        <span className="loading" style={ {float: 'right' } }>
                                            <img
                                                className="loading"
                                                src={Link.get('static', 'loading-16.gif')}
                                            /> loading more data...
                                        </span> : null
                                }
                            </td>
                        </tr>
                    </tfoot> : null
                }
            </table>
        );
    },
});
