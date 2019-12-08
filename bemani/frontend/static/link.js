var Link = {
    // Helper for taking server-rendered links with a component that we want
    // to change client-side, and updating them based on parameters.

    get: function(name, param, anchor) {
        var uri = window.uris[name];
        if (!param || !uri) {
            return uri;
        } else if (!anchor) {
            return uri.replace("/-1", "/" + param.toString());
        } else {
            return uri.replace("/-1", "/" + param.toString()) + '#' + anchor.toString();
        }
    },
};
