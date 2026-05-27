(function () {
  var els = document.querySelectorAll(".fade-in");
  if (els.length && "IntersectionObserver" in window) {
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          obs.unobserve(entry.target);
        }
      });
    }, { rootMargin: "0px 0px -10% 0px", threshold: 0.05 });
    els.forEach(function (el) { obs.observe(el); });
  } else if (els.length) {
    els.forEach(function (el) { el.classList.add("is-visible"); });
  }

  function initSectionNav(navRoot, linkSelector) {
    var navAnchors = navRoot.querySelectorAll(linkSelector);
    if (!navAnchors.length || !("IntersectionObserver" in window)) return;

    var navSections = [];
    navAnchors.forEach(function (link) {
      var id = link.getAttribute("data-nav");
      var section = document.getElementById(id);
      if (section) navSections.push({ id: id, el: section });
    });

    if (!navSections.length) return;

    var setActiveNav = function (id) {
      navAnchors.forEach(function (link) {
        link.classList.toggle("is-active", !!id && link.getAttribute("data-nav") === id);
      });
    };

    var navObs = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        entry.target.dataset.navVisible = entry.isIntersecting ? String(entry.intersectionRatio) : "0";
      });
      var bestId = null;
      var bestRatio = 0;
      navSections.forEach(function (item) {
        var ratio = parseFloat(item.el.dataset.navVisible || "0", 10);
        if (ratio > bestRatio) {
          bestRatio = ratio;
          bestId = item.id;
        }
      });
      setActiveNav(bestRatio > 0 ? bestId : null);
    }, { rootMargin: "-42% 0px -42% 0px", threshold: [0, 0.15, 0.4] });

    navSections.forEach(function (item) { navObs.observe(item.el); });
  }

  var homeBar = document.querySelector(".home-bar");
  if (!homeBar) return;

  var homeToggle = homeBar.querySelector(".home-bar__toggle");
  var homeMenu = document.getElementById("home-bar-menu");

  if (homeToggle && homeMenu) {
    function setHomeOpen(open) {
      homeBar.classList.toggle("is-open", open);
      homeToggle.setAttribute("aria-expanded", open ? "true" : "false");
      homeToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    }

    homeToggle.addEventListener("click", function () {
      setHomeOpen(!homeBar.classList.contains("is-open"));
    });

    homeMenu.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () { setHomeOpen(false); });
    });

    window.addEventListener("resize", function () {
      if (window.matchMedia("(min-width: 769px)").matches) setHomeOpen(false);
    });
  }

  initSectionNav(homeBar, ".home-bar__link[data-nav]");
})();
