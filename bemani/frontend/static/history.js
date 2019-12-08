function History (valid_states, valid_substates) {
    // Handles allowing client-side react to add to/interact with browser
    // history. This is how we can allow linking directly to a particular
    // view while still being client-side JS.

    this.valid_states = valid_states;
    if (valid_substates) {
        this.valid_substates = valid_substates;
    } else {
        // Just init to nothing for each, so we won't add commas to URIs
        this.valid_substates = valid_states.map(function(state) {
            return null;
        }.bind(this));
    }

    this.__lookup = function(hash) {
        var state = null;
        var substate = null;

        if (hash) {
            this.valid_states.forEach(function(valid_state, index) {
                if (this.valid_substates[index]) {
                    var parts = hash.split(',');
                    if (parts[0] == valid_state) {
                        this.valid_substates[index].forEach(function(valid_substate) {
                            if (parts[1] == valid_substate) {
                                state = valid_state;
                                substate = valid_substate;
                            }
                        }.bind(this));
                    }
                } else {
                    if (hash == valid_state) {
                        state = valid_state;
                        substate = null;
                    }
                }
            }.bind(this));
        }

        return {
            state: state,
            substate: substate,
        };
    };

    this.__hash = function() {
        return decodeURIComponent(window.location.href.split('#')[1]);
    }

    this.__construct = function(stateobj) {
        if (stateobj.substate) {
            return stateobj.state+','+stateobj.substate;
        } else {
            return stateobj.state;
        }
    };

    this.getInitialState = function(default_state, default_substate) {
        var state = this.__hash();
        var actualState = this.__lookup(state);

        if (actualState.state) {
            history.replaceState({}, null, '#'+this.__construct(actualState));
            return actualState.state;
        } else {
            history.replaceState({}, null, '#'+this.__construct({state: default_state, substate: default_substate}));
            return default_state;
        }
    };

    this.getInitialSubState = function(default_state, default_substate) {
        var state = this.__hash();
        var actualState = this.__lookup(state);

        if (actualState.state) {
            history.replaceState({}, null, '#'+this.__construct(actualState));
            return actualState.substate;
        } else {
            history.replaceState({}, null, '#'+this.__construct({state: default_state, substate: default_substate}));
            return default_substate;
        }
    };

    this.onChange = function(callback) {
        window.onpopstate = function(event) {
            var state = this.__hash();
            var actualState = this.__lookup(state);
            if (actualState.state) {
                callback(actualState.state, actualState.substate);
            }
        }.bind(this);
    };

    this.navigate = function(state, substate) {
        var actualState = this.__lookup(this.__construct({state: state, substate: substate}));
        if (actualState.state) {
            history.pushState({}, null, '#'+this.__construct(actualState));
        }
    };
};
