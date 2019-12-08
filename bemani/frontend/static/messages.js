var Messages = {
    error: function(message) {
        $("ul.messages").append("<li class=\"error\">" + message + "<div class=\"close\">&#10005;</div></li>");
        window.floaterrors(true);
    },

    warning: function(message) {
        $("ul.messages").append("<li class=\"warning\">" + message + "<div class=\"close\">&#10005;</div></li>");
        window.floaterrors(true);
    },

    success: function(message) {
        $("ul.messages").append("<li class=\"success\">" + message + "<div class=\"close\">&#10005;</div></li>");
        window.floaterrors(true);
    },

    info: function(message) {
        $("ul.messages").append("<li class=\"info\">" + message + "<div class=\"close\">&#10005;</div></li>");
        window.floaterrors(true);
    },
};
