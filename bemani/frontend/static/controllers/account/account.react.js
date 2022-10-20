/*** @jsx React.DOM */

var account_management = createReactClass({
    getInitialState: function(props) {
        return {
            email: window.email,
            new_email: window.email,
            email_password: '',
            editing_email: false,
            username: window.username,
            editing_pin: false,
            new_pin: '',
            editing_password: false,
            old_password: '',
            new_password1: '',
            new_password2: '',
        };
    },

    componentDidUpdate: function() {
        if (this.focus_element && this.focus_element != this.already_focused) {
            this.focus_element.focus();
            this.already_focused = this.focus_element;
        }
    },

    saveEmail: function(event) {
        AJAX.post(
            Link.get('updateemail'),
            {
                email: this.state.new_email,
                password: this.state.email_password,
            },
            function(response) {
                this.setState({
                    email: response.email,
                    new_email: response.email,
                    email_password: '',
                    editing_email: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    savePin: function(event) {
        AJAX.post(
            Link.get('updatepin'),
            {pin: this.state.new_pin},
            function(response) {
                this.setState({
                    new_pin: '',
                    editing_pin: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    savePassword: function(event) {
        AJAX.post(
            Link.get('updatepassword'),
            {
                old: this.state.old_password,
                new1: this.state.new_password1,
                new2: this.state.new_password2,
            },
            function(response) {
                this.setState({
                    old_password: '',
                    new_password1: '',
                    new_password2: '',
                    editing_password: false,
                });
            }.bind(this)
        );
        event.preventDefault();
    },

    renderUsername: function() {
        return (
            <LabelledSection vertical={true} label="Username">{ this.state.username }</LabelledSection>
        );
    },

    renderPassword: function() {
        return (
            <LabelledSection vertical={true} label="Password">{
                !this.state.editing_password ?
                    <>
                        <span>&bull;&bull;&bull;&bull;&bull;&bull;</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_password: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.savePassword}>
                        <div>
                            <label for="old">Current password:</label>
                            <input
                                type="password"
                                autofocus="true"
                                ref={c => (this.focus_element = c)}
                                value={this.state.old_password}
                                onChange={function(event) {
                                    this.setState({old_password: event.target.value});
                                }.bind(this)}
                                name="old"
                            />
                        </div>
                        <div>
                            <label for="new1">New password:</label>
                            <input
                                type="password"
                                value={this.state.new_password1}
                                onChange={function(event) {
                                    this.setState({new_password1: event.target.value});
                                }.bind(this)}
                                name="new1"
                            />
                        </div>
                        <div>
                            <label for="new2">New password (again):</label>
                            <input
                                type="password"
                                value={this.state.new_password2}
                                onChange={function(event) {
                                    this.setState({new_password2: event.target.value});
                                }.bind(this)}
                                name="new2"
                            />
                        </div>
                        <div className="buttons">
                            <input
                                type="submit"
                                value="save"
                            />
                            <input
                                type="button"
                                value="cancel"
                                onClick={function(event) {
                                    this.setState({
                                        old_password: '',
                                        new_password1: '',
                                        new_password2: '',
                                        editing_password: false,
                                    });
                                }.bind(this)}
                            />
                        </div>
                    </form>
            }</LabelledSection>
        );
    },

    renderEmail: function() {
        return (
            <LabelledSection vertical={true} label="Email Address">{
                !this.state.editing_email ?
                    <>
                        <span>{ this.state.email }</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_email: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.saveEmail}>
                        <div>
                            <label for="old">Current password:</label>
                            <input
                                type="password"
                                autofocus="true"
                                ref={c => (this.focus_element = c)}
                                value={this.state.email_password}
                                onChange={function(event) {
                                    this.setState({email_password: event.target.value});
                                }.bind(this)}
                                name="old"
                            />
                        </div>
                        <div>
                            <label for="email">New email address:</label>
                            <input
                                type="text"
                                value={this.state.new_email}
                                onChange={function(event) {
                                    this.setState({new_email: event.target.value});
                                }.bind(this)}
                                name="email"
                            />
                        </div>
                        <div className="buttons">
                            <input
                                type="submit"
                                value="save"
                            />
                            <input
                                type="button"
                                value="cancel"
                                onClick={function(event) {
                                    this.setState({
                                        new_email: this.state.email,
                                        email_password: '',
                                        editing_email: false,
                                    });
                                }.bind(this)}
                            />
                        </div>
                    </form>
            }</LabelledSection>
        );
    },

    renderPIN: function() {
        return (
            <LabelledSection vertical={true} label="PIN">{
                !this.state.editing_pin ?
                    <>
                        <span>&bull;&bull;&bull;&bull;</span>
                        <Edit
                            onClick={function(event) {
                                this.setState({editing_pin: true});
                            }.bind(this)}
                        />
                    </> :
                    <form className="inline" onSubmit={this.savePin}>
                        <input
                            type="text"
                            className="inline"
                            maxlength="4"
                            size="4"
                            autofocus="true"
                            ref={c => (this.focus_element = c)}
                            value={this.state.new_pin}
                            onChange={function(event) {
                                var intRegex = /^\d*$/;
                                if (event.target.value.length <= 4 && intRegex.test(event.target.value)) {
                                    this.setState({new_pin: event.target.value});
                                }
                            }.bind(this)}
                            name="pin"
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
                                    new_pin: '',
                                    editing_pin: false,
                                });
                            }.bind(this)}
                        />
                    </form>
            }</LabelledSection>
        );
    },

    render: function() {
        return (
            <div>
                <div className="section">
                    {this.renderUsername()}
                    {this.renderPassword()}
                    {this.renderEmail()}
                    {this.renderPIN()}
                </div>
            </div>
        );
    },
});

ReactDOM.render(
    React.createElement(account_management, null),
    document.getElementById('content')
);
