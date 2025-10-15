var script = document.createElement("script");

script.setAttribute("async", "");
script.setAttribute("src", "https://umami.suricata-check.teuwen.net/script.js");
script.setAttribute("data-website-id", "29b9bc19-67b0-414d-98d2-ea099ec5149a");
script.setAttribute("data-do-not-track", "true");
script.setAttribute("data-domains", "suricata-check-design-principles.teuwen.net");

window.addEventListener('load', function () {
    document.body.appendChild(script);

    (() => {
        const name = 'internal-link-click';
        document.querySelectorAll('a').forEach(a => {
            if (a.host === window.location.host && !a.getAttribute('data-umami-event')) {
                a.setAttribute('data-umami-event', name);
                a.setAttribute('data-umami-event-source', window.location.href);
                a.setAttribute('data-umami-event-target', a.href);
            }
        });
    })();
    
    (() => {
        const name = 'outbound-link-click';
        document.querySelectorAll('a').forEach(a => {
            if (a.host !== window.location.host && !a.getAttribute('data-umami-event')) {
                a.setAttribute('data-umami-event', name);
                a.setAttribute('data-umami-event-source', window.location.href);
                a.setAttribute('data-umami-event-target', a.href);
            }
        });
    })();
});
