function getGuardApiURL() {
    let url = new URL(window.location.href);
    url.port = window.location.port;
    url.pathname = "/guard/api";

    if (window.location.hostname == "localhost" || window.location.hostname == "127.0.0.1") {
        if (typeof localStorage != "undefined") {
            const custom_api_endpoint = localStorage.getItem("custom_guard_api_endpoint");
            if (custom_api_endpoint) {
                url.href = custom_api_endpoint;
            }
        }
    } else {
        url.protocol = "https:";
    }

    url.search = '';

    return url.href;
}

export { getGuardApiURL };