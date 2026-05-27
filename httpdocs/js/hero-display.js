(function () {
  var root = document.getElementById("hero-display");
  if (!root) return;

  var screen = root.querySelector(".hero-display__screen");
  var content = root.querySelector(".hero-display__content");
  var caption = root.querySelector(".hero-display__caption");
  if (!screen || !content || !caption) return;

  var slides = [
    {
      caption: "Weather on the way out",
      label: "WED · OUT",
      value: "14°",
      meta: '<span class="ink-red">rain in 12m</span> · radar 2km'
    },
    {
      caption: "Picture frame, in six colors",
      spectra: true
    },
    {
      caption: "Pollen before you commute",
      label: "THU · POLLEN",
      value: "Med",
      valueClass: "ink-yellow",
      meta: "grasses · oak"
    },
    {
      caption: "Did I take it today?",
      label: "MEDS",
      value: 'AM ✓ <span class="ink-red">PM ·</span>',
      meta: "last 08:14"
    },
    {
      caption: "Next-meeting reminder",
      label: "NEXT · 09:30",
      value: "Standup",
      meta: '<span class="ink-yellow">in 12 min</span>'
    },
    {
      caption: "Energy used today",
      label: "TODAY · ENERGY",
      value: "4.3 kWh",
      meta: "peak 12:00 · −8% wow"
    }
  ];

  var index = 0;
  var holdMs = 5000;
  var fadeMs = 900;
  var timer = null;
  var reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function renderSlide(slide) {
    screen.classList.toggle("hero-display__screen--spectra", !!slide.spectra);

    if (slide.spectra) {
      content.className = "hero-display__content collage__content hero-display__content--spectra";
      content.innerHTML = '<div class="hero-display__spectra-photo" aria-hidden="true"></div>';
    } else {
      content.className = "hero-display__content collage__content";
      var valueClass = slide.valueClass ? "collage__value " + slide.valueClass : "collage__value";
      content.innerHTML =
        '<div class="collage__label">' + slide.label + "</div>" +
        '<div class="' + valueClass + '">' + slide.value + "</div>" +
        '<div class="collage__meta">' + slide.meta + "</div>";
    }

    caption.textContent = slide.caption;
  }

  function nextIndex() {
    index = (index + 1) % slides.length;
    return index;
  }

  function wait(ms) {
    return new Promise(function (resolve) {
      timer = window.setTimeout(resolve, ms);
    });
  }

  function flashToNext() {
    root.classList.add("is-flashing");
    return wait(fadeMs).then(function () {
      renderSlide(slides[nextIndex()]);
      root.classList.remove("is-flashing");
      return wait(fadeMs);
    });
  }

  function loop() {
    flashToNext().then(function () {
      timer = window.setTimeout(loop, holdMs);
    });
  }

  renderSlide(slides[0]);

  if (reducedMotion) return;

  timer = window.setTimeout(loop, holdMs);

  document.addEventListener("visibilitychange", function () {
    if (document.hidden && timer) {
      window.clearTimeout(timer);
      timer = null;
    } else if (!document.hidden && !timer && !reducedMotion) {
      timer = window.setTimeout(loop, holdMs);
    }
  });
})();
