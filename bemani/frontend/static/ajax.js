var AJAX = {
    get: function(url, resp) {
        $.ajax({
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            url: url,
            success: function(response) {
                if (response.error) {
                    Messages.error(response.message);
                } else {
                    resp(response);
                }
            },
        });
    },

    post: function(url, data, resp) {
        $.ajax({
            type: "POST",
            dataType: "json",
            contentType: "application/json; charset=utf-8",
            url: url,
            data: JSON.stringify(data),
            success: function(response) {
                if (response.error) {
                    Messages.error(response.message);
                } else {
                    resp(response);
                }
            },
        });
    },
};
