var Link = {
    // Helper for taking server-rendered links with a component that we want
    // to change client-side, and updating them based on parameters.

    get: function(name, param, anchor) {
        var uri = window.uris[name];
        if (!param || !uri) {
            if (!anchor) {
                return uri;
            } else {
                return uri + '#' + anchor.toString();
            }
        } else if (!anchor) {
            return uri.replace("/-1", "/" + param.toString());
        } else {
            return uri.replace("/-1", "/" + param.toString()) + '#' + anchor.toString();
        }
    },
};
