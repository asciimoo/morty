(function(w, d) {
    "use strict";

    var pathname = d.location.pathname;
    if (pathname === "/post") {
        pathname = "/";
    }
    var morty_path = d.location.protocol + "//" + d.location.host + pathname;
    var checked_uri = {};
    var current_div = false;

    function is_morty_uri(uri) {
        return uri.startsWith(morty_path);
    }

    function check() {
        // check leaked_uris
        var resources = w.performance.getEntriesByType("resource");
        var leaked_uris = [];
        var new_leaked_uris = false;
        var uri;
        resources.forEach(function(resource) {
            uri = resource.name;
            if (! is_morty_uri(uri)) {
	        leaked_uris.push(uri);
                if ((typeof checked_uri[uri]) === "undefined") {
                    new_leaked_uris = true;
                    console.error("Morty, leaked URI: " + uri);
                }
                checked_uri[uri] = true;
            }
        });

        // is there a leak ?
        if (new_leaked_uris) {
            // there is a leak
            // create the div if first time
            if (current_div === false) {
                current_div = d.createElement("div");
                d.getElementById("mortyheader").parentNode.appendChild(current_div);
            }
            // display
            var content ="<h1 style=\"margin:0;padding:0\">Morty : Leak detected</h1><ul>";
            Object.keys(leaked_uris).forEach(function (uri) {
	        content += "<li>" + leaked_uris[uri] + "</li>";
            });
            content += "</ul>";

            current_div.innerHTML = content;
            current_div.style = "position:fixed; top:0; left:0; right:0; border: 4px solid #BC1A1A; padding: 12px; font-size: 12px !important; font-family: sans !important; line-height: 1em; background: white; color:black; z-index: 220000; overflow:hidden; word-wrap:break-word;";
        }

        // check every second
        w.setTimeout(check, 1000);
    }

    if ( ("performance" in w) &&
         ("getEntriesByType" in w.performance) &&
         (w.performance.getEntriesByType("resource") instanceof Array)
       ) {
        check();
    }

})(window, document);

/*global console, window, document */
