(function () {
  /* Hardcoded from firmware/toolbox/simple-config-presets.json — ordered by screen size */
  var PANELS = [
    { id: "ep42yr-400x300", label: "4.2″ BWRY", fullUpdateMc: 165 },
    { id: "ep426-800x480", label: "4.26″ mono", fullUpdateMc: 38 },
    { id: "ep73-spectra-800x480", label: "7.3″ Spectra 6", fullUpdateMc: 400 },
    { id: "ep75-800x480", label: "7.5″ mono", fullUpdateMc: 100 }
  ];

  var CHIPS = [
    { id: "nrf52840", label: "nRF52840", sub: "Nordic", standbyUa: 300 },
    { id: "silabs", label: "EFR32BG22", sub: "Silicon Labs", standbyUa: 20 },
    { id: "esp32", label: "ESP32", sub: "Espressif", standbyMa: 80 }
  ];

  /* battery-prim-1p, battery-prim-2p, battery-2000, battery-4000 */
  var BATTERIES = [
    { id: "cr2450", label: "CR2450", sub: "600 mAh", capacity: 600, family: "coin" },
    { id: "cr2450x2", label: "2× CR2450", sub: "1200 mAh", capacity: 1200, family: "coin2" },
    { id: "lipo2000", label: "LiPo", sub: "2000 mAh", capacity: 2000, family: "lipo" },
    { id: "lipo4000", label: "LiPo", sub: "4000 mAh", capacity: 4000, family: "lipo" }
  ];

  var root = document.getElementById("battery-widget");
  if (!root) return;

  var panelId = "ep426-800x480";
  var batteryId = "lipo2000";
  var chipId = "silabs";
  var intervalMin = 120;

  var elCapacity = root.querySelector("[data-batt-capacity]");
  var elInterval = root.querySelector("[data-batt-interval]");
  var elStandby = root.querySelector("[data-batt-standby]");
  var elLifeValue = root.querySelector("[data-batt-life-value]");
  var elLifeUnit = root.querySelector("[data-batt-life-unit]");
  var elLifeSub = root.querySelector("[data-batt-life-sub]");
  var elRefreshPct = root.querySelector("[data-batt-refresh-pct]");
  var elRefreshMah = root.querySelector("[data-batt-refresh-mah]");
  var elRefreshSub = root.querySelector("[data-batt-refresh-sub]");
  var elStandbyPct = root.querySelector("[data-batt-standby-pct]");
  var elStandbyMah = root.querySelector("[data-batt-standby-mah]");
  var elStandbySub = root.querySelector("[data-batt-standby-sub]");
  var elDailyMah = root.querySelector("[data-batt-daily-mah]");
  var elDailySub = root.querySelector("[data-batt-daily-sub]");
  var elEspWarn = root.querySelector("[data-batt-esp-warn]");
  var elRange = root.querySelector("[data-batt-range]");
  var displayPicker = root.querySelector('[data-picker-group="display"]');
  var chipPicker = root.querySelector('[data-picker-group="chip"]');

  var CHIP_SVG =
    '<svg width="28" height="22" viewBox="0 0 28 22" fill="none" aria-hidden="true">' +
    '<rect x="6" y="3" width="16" height="16" rx="1.5" stroke="currentColor" stroke-width="1.5"/>' +
    '<rect x="10" y="7" width="8" height="8" rx="0.5" stroke="currentColor" stroke-width="0.8"/>' +
    '<path d="M3 7h3M3 11h3M3 15h3M22 7h3M22 11h3M22 15h3M9 1v2M14 1v2M19 1v2M9 19v2M14 19v2M19 19v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>' +
    "</svg>";

  function chipStandbyUa(chip) {
    if (chip.standbyMa) return chip.standbyMa * 1000;
    return chip.standbyUa;
  }

  function formatChipStandby(chip) {
    if (chip.standbyMa) return chip.standbyMa + " mA idle";
    return chip.standbyUa + " µA standby";
  }

  function formatChipStandbySub(chip) {
    if (chip.standbyMa) return chip.standbyMa + " mA × 24 h · " + chip.label + " idle";
    return chip.standbyUa + " µA × 24 h · " + chip.label + " deep sleep";
  }

  function findBattery(id) {
    for (var i = 0; i < BATTERIES.length; i++) {
      if (BATTERIES[i].id === id) return BATTERIES[i];
    }
    return BATTERIES[0];
  }

  function findChip(id) {
    for (var i = 0; i < CHIPS.length; i++) {
      if (CHIPS[i].id === id) return CHIPS[i];
    }
    return CHIPS[0];
  }

  function findPanel(id) {
    for (var i = 0; i < PANELS.length; i++) {
      if (PANELS[i].id === id) return PANELS[i];
    }
    return PANELS[1];
  }

  function panelSub(panel) {
    return panel.fullUpdateMc + " mC/update";
  }

  function formatInterval(min) {
    if (min < 60) return "every " + min + " min";
    var h = min / 60;
    return "every " + (min % 60 === 0 ? h : h.toFixed(1)) + " h";
  }

  function formatLife(days) {
    if (!isFinite(days) || days <= 0) return { value: "—", unit: "", sub: "—" };
    var years = days / 365;
    if (years >= 1) {
      var yWhole = Math.floor(years);
      var monthsRest = Math.round((years - yWhole) * 12);
      var sub = yWhole >= 5
        ? Math.round(days).toLocaleString() + " days at this rate"
        : yWhole + " yr " + monthsRest + " mo · " + Math.round(days).toLocaleString() + " days";
      return {
        value: years.toFixed(years >= 10 ? 0 : 1),
        unit: "years",
        sub: sub
      };
    }
    if (days >= 30) {
      return {
        value: (days / 30).toFixed(1),
        unit: "months",
        sub: Math.round(days) + " days at this rate"
      };
    }
    return {
      value: String(Math.round(days)),
      unit: "days",
      sub: "≈ " + Math.round(days * 24) + " hours of run time"
    };
  }

  function setActivePicker(group, id) {
    root.querySelectorAll('[data-picker-group="' + group + '"] .batt-pick').forEach(function (btn) {
      var active = btn.getAttribute("data-id") === id;
      btn.classList.toggle("batt-pick--active", active);
      btn.setAttribute("aria-pressed", active ? "true" : "false");
    });
  }

  function buildDisplayPickers() {
    if (!displayPicker) return;
    displayPicker.innerHTML = "";
    PANELS.forEach(function (panel) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "batt-pick batt-pick--display" + (panel.id === panelId ? " batt-pick--active" : "");
      btn.setAttribute("data-id", panel.id);
      btn.setAttribute("aria-pressed", panel.id === panelId ? "true" : "false");
      btn.innerHTML =
        '<span class="batt-pick__label">' + panel.label + "</span>" +
        '<span class="batt-pick__sub">' + panelSub(panel) + "</span>";
      btn.addEventListener("click", function () {
        panelId = panel.id;
        render();
      });
      displayPicker.appendChild(btn);
    });
  }

  function buildChipPickers() {
    if (!chipPicker) return;
    chipPicker.innerHTML = "";
    CHIPS.forEach(function (chip) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "batt-pick" + (chip.id === chipId ? " batt-pick--active" : "");
      btn.setAttribute("data-id", chip.id);
      btn.setAttribute("aria-pressed", chip.id === chipId ? "true" : "false");
      btn.innerHTML =
        CHIP_SVG +
        '<span class="batt-pick__label">' + chip.label + "</span>" +
        '<span class="batt-pick__sub">' + chip.sub + "</span>";
      btn.addEventListener("click", function () {
        chipId = chip.id;
        render();
      });
      chipPicker.appendChild(btn);
    });
  }

  function render() {
    var battery = findBattery(batteryId);
    var chip = findChip(chipId);
    var panel = findPanel(panelId);
    var capacity = battery.capacity;
    var standbyUa = chipStandbyUa(chip);
    var refreshMc = panel.fullUpdateMc;
    var intervalS = Math.max(1, intervalMin * 60);
    var dailyUpdates = 86400 / intervalS;
    var refreshMah = refreshMc / 3600;
    var dailyRefreshMah = refreshMah * dailyUpdates;
    var dailyStandbyMah = standbyUa * 24 / 1000;
    var dailyMah = dailyRefreshMah + dailyStandbyMah;
    var lifeDays = capacity / dailyMah;
    var life = formatLife(lifeDays);
    var refreshPct = dailyMah > 0 ? (dailyRefreshMah / dailyMah) * 100 : 0;
    var standbyPct = 100 - refreshPct;

    elCapacity.textContent = capacity.toLocaleString() + " mAh";
    elInterval.textContent = formatInterval(intervalMin);
    elStandby.textContent = formatChipStandby(chip);
    elLifeValue.textContent = life.value;
    elLifeUnit.textContent = life.unit;
    elLifeSub.textContent = life.sub;
    elRefreshPct.textContent = "Refresh draw · " + refreshPct.toFixed(0) + "%";
    elRefreshMah.innerHTML = (refreshMah * 1000).toFixed(2) + '<span class="batt-bd-unit"> µAh / update</span>';
    elRefreshSub.textContent = refreshMc + " mC/update · " + panel.label;
    elStandbyPct.textContent = "Standby draw · " + standbyPct.toFixed(0) + "%";
    elStandbyMah.innerHTML = dailyStandbyMah.toFixed(2) + '<span class="batt-bd-unit"> mAh / day</span>';
    elStandbySub.textContent = formatChipStandbySub(chip);
    elDailyMah.innerHTML = dailyMah.toFixed(2) + '<span class="batt-bd-unit"> mAh / day</span>';
    elDailySub.textContent = Math.round(lifeDays).toLocaleString() + " days from one charge";

    if (elEspWarn) elEspWarn.hidden = chipId !== "esp32";

    setActivePicker("battery", batteryId);
    setActivePicker("chip", chipId);
    setActivePicker("display", panelId);
  }

  buildDisplayPickers();
  buildChipPickers();

  root.querySelectorAll('[data-picker-group="battery"] .batt-pick').forEach(function (btn) {
    btn.addEventListener("click", function () {
      batteryId = btn.getAttribute("data-id");
      render();
    });
  });

  elRange.addEventListener("input", function () {
    intervalMin = parseInt(elRange.value, 10);
    render();
  });

  render();
})();
