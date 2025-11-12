var script = document.createElement("script");

script.setAttribute("async", "");
script.setAttribute("src", "https://umami.suricata-check.teuwen.net/script.js");
script.setAttribute("data-website-id", "c302c87d-bf3a-4c62-8b6b-8a17d7bf20d4");
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
