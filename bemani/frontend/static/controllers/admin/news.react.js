/*** @jsx React.DOM */

var news_management = createReactClass({
    getInitialState: function(props) {
        return {
            news: window.news,
            editing_news: null,
            new_entry: {
                title: '',
                body: '',
            },
        };
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    deleteExistingNews: function(event, newsid) {
        $.confirm({
            escapeKey: 'Cancel',
            animation: 'none',
            closeAnimation: 'none',
            title: 'Delete Entry',
            content: 'Are you sure you want to delete this news entry?',
            buttons: {
                Delete: {
                    btnClass: 'delete',
                    action: function() {
                        AJAX.post(
                            Link.get('removenews'),
                            {newsid: newsid},
                            function(response) {
                                this.setState({
                                    news: response.news,
                                });
                            }.bind(this)
                        );
                    }.bind(this),
                },
                Cancel: function() {
                },
            }
        });
        event.preventDefault();
    },

    addNews: function(event) {
        AJAX.post(
            Link.get('addnews'),
            {news: this.state.new_entry},
            function(response) {
                this.setState({
                    news: response.news,
                    new_entry: {
                        title: '',
                        body: '',
                    },
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    saveNews: function(event) {
        AJAX.post(
            Link.get('updatenews'),
            {news: this.state.editing_news},
            function(response) {
                this.setState({
                    news: response.news,
                    editing_news: null,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    previewNews: function(event, entry) {
        $.confirm({
            escapeKey: 'Close',
            animation: 'none',
            closeAnimation: 'none',
            title: entry.title.length > 0 ? entry.title : 'No Title',
            content: entry.body.length > 0 ? entry.body : 'No body.',
            buttons: {
                Close: function() {
                },
            }
        });
        event.preventDefault();
    },

    renderDate: function(entry) {
        return (
            <Timestamp timestamp={entry.timestamp} />
        );
    },

    renderTitle: function(entry) {
        if (this.state.editing_news && entry.id == this.state.editing_news.id) {
            return (
                <input
                    name="title"
                    type="text"
                    autofocus="true"
                    ref={c => (this.focus_element = c)}
                    value={ this.state.editing_news.title }
                    onChange={function(event) {
                        var entry = this.state.editing_news;
                        entry.title = event.target.value;
                        this.setState({
                            editing_news: entry,
                        });
                    }.bind(this)}
                />
            );
        } else {
            return (
                <span>{ entry.title }</span>
            );
        }
    },

    renderBody: function(entry) {
        if (this.state.editing_news && entry.id == this.state.editing_news.id) {
            return (
                <textarea
                    name="body"
                    cols="60"
                    rows="10"
                    value={ this.state.editing_news.body }
                    onChange={function(event) {
                        var entry = this.state.editing_news;
                        entry.body = event.target.value;
                        this.setState({
                            editing_news: entry,
                        });
                    }.bind(this)}
                />
            );
        } else {
            return (
                <span>{ entry.body }</span>
            );
        }
    },

    renderEditButton: function(entry) {
        if (this.state.editing_news) {
            if (this.state.editing_news.id == entry.id) {
                return (
                    <>
                        <input
                            type="button"
                            value="preview"
                            onClick={function(event) {
                                this.previewNews(event, this.state.editing_news);
                            }.bind(this)}
                        />
                        <input
                            type="submit"
                            value="save"
                        />
                        <input
                            type="button"
                            value="cancel"
                            onClick={function(event) {
                                this.setState({
                                    editing_news: null,
                                });
                            }.bind(this)}
                        />
                    </>
                );
            } else {
                return null;
            }
        } else {
            return (
                <>
                    <Edit
                        onClick={function(event) {
                            var editing_news = null;
                            this.state.news.map(function(a) {
                                if (a.id == entry.id) {
                                    editing_news = jQuery.extend(true, {}, a);
                                }
                            });
                            this.setState({
                                editing_news: editing_news,
                            });
                        }.bind(this)}
                    />
                    <Delete
                        onClick={function(event) {
                            this.deleteExistingNews(event, entry.id);
                        }.bind(this)}
                    />
                </>
            );
        }
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    { this.state.news.length > 0 ?
                        <form className="inline" onSubmit={this.saveNews}>
                            <table className="list news">
                                <thead>
                                    <tr>
                                        <th>Date</th>
                                        <th>Title</th>
                                        <th>Body</th>
                                        <th className="action"></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {
                                        this.state.news.map(function(entry) {
                                            return (
                                                <tr>
                                                    <td>{ this.renderDate(entry) }</td>
                                                    <td>{ this.renderTitle(entry) }</td>
                                                    <td>{ this.renderBody(entry) }</td>
                                                    <td className="edit">{ this.renderEditButton(entry) }</td>
                                                </tr>
                                            );
                                        }.bind(this))
                                    }
                                </tbody>
                            </table>
                        </form> :
                        <span className="placeholder">
                            There are no news entries on this network.
                        </span>
                    }
                </div>
                <div className="section">
                    <h3>Add Entry</h3>
                    <form className="inline" onSubmit={this.addNews}>
                        <LabelledSection vertical={true} label="Title">
                            <input
                                name="title"
                                type="text"
                                size="50"
                                value={ this.state.new_entry.title }
                                onChange={function(event) {
                                    var entry = this.state.new_entry;
                                    entry.title = event.target.value;
                                    this.setState({new_entry: entry});
                                }.bind(this)}
                            />
                        </LabelledSection>
                        <LabelledSection vertical={true} label="Body">
                            <textarea
                                name="body"
                                cols="80"
                                rows="10"
                                value={ this.state.new_entry.body }
                                onChange={function(event) {
                                    var entry = this.state.new_entry;
                                    entry.body = event.target.value;
                                    this.setState({new_entry: entry});
                                }.bind(this)}
                            />
                        </LabelledSection>
                        <LabelledSection vertical={true}>
                            <input
                                type="button"
                                value="preview"
                                onClick={function(event) {
                                    this.previewNews(event, this.state.new_entry);
                                }.bind(this)}
                            />
                            <input
                                type="submit"
                                value="post"
                            />
                        </LabelledSection>
                    </form>
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(news_management, null),
    document.getElementById('content')
);
