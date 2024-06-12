function getGuardApiURL() {
    let url = new URL(window.location.href);
    url.port = window.location.port;
    if (window.location.hostname == "127.0.0.1") {
        url.port = 8000;
    }
    url.pathname = "/api";

    if (window.location.protocol == "http:") {
        if (window.location.hostname == "localhost" || window.location.hostname == "127.0.0.1") {
            url.protocol = "http:";
        }
    }
    
    url.searchParams.forEach((key, value) => {
        url.searchParams.delete(key, value);
    });
    
    return `${url.protocol}//${url.host}/guard/api`;
}

export { getGuardApiURL };