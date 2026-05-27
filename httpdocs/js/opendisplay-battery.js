/**
 * Battery state-of-charge estimation from cell voltage (OpenDisplay py-opendisplay/battery.py).
 * All curves assume single-cell voltages measured at rest (no load).
 */
(function (global) {
  'use strict';

  var CapacityEstimator = {
    LI_ION: 1,
    LIFEPO4: 2,
    SUPERCAP: 3,
    LITHIUM_PRIMARY: 4
  };

  var SOC_LI_ION = [
    [4200, 100], [4150, 95], [4110, 90], [4080, 85], [4020, 80], [3980, 75],
    [3950, 70], [3910, 65], [3870, 60], [3830, 55], [3790, 50], [3750, 45],
    [3710, 40], [3670, 35], [3630, 30], [3590, 25], [3550, 20], [3490, 15],
    [3430, 10], [3350, 5], [3000, 0]
  ];

  var SOC_LIFEPO4 = [
    [3650, 100], [3400, 90], [3350, 80], [3320, 70], [3290, 60], [3270, 50],
    [3250, 40], [3220, 30], [3200, 20], [3000, 10], [2500, 0]
  ];

  var SOC_LITHIUM_PRIMARY = [
    [3000, 100], [2600, 0]
  ];

  var SOC_SUPERCAP = [
    [4500, 100], [3000, 0]
  ];

  var CHEMISTRY_LABELS = {
    1: 'Li-Ion',
    2: 'LiFePO4',
    3: 'Supercap',
    4: 'Lithium primary'
  };

  function interpolate(table, voltageMv) {
    if (voltageMv >= table[0][0]) return table[0][1];
    if (voltageMv <= table[table.length - 1][0]) return table[table.length - 1][1];
    for (var i = 0; i < table.length - 1; i++) {
      var vHigh = table[i][0];
      var socHigh = table[i][1];
      var vLow = table[i + 1][0];
      var socLow = table[i + 1][1];
      if (voltageMv >= vLow && voltageMv <= vHigh) {
        var ratio = (voltageMv - vLow) / (vHigh - vLow);
        return Math.round(socLow + ratio * (socHigh - socLow));
      }
    }
    return 0;
  }

  function voltageToPercent(voltageMv, chemistry) {
    var c = chemistry | 0;
    switch (c) {
      case CapacityEstimator.LI_ION:
        return interpolate(SOC_LI_ION, voltageMv);
      case CapacityEstimator.LIFEPO4:
        return interpolate(SOC_LIFEPO4, voltageMv);
      case CapacityEstimator.LITHIUM_PRIMARY:
        return interpolate(SOC_LITHIUM_PRIMARY, voltageMv);
      case CapacityEstimator.SUPERCAP:
        return interpolate(SOC_SUPERCAP, voltageMv);
      default:
        return null;
    }
  }

  function chemistryLabel(chemistry) {
    return CHEMISTRY_LABELS[chemistry | 0] || null;
  }

  function formatSocLine(voltageMv, chemistry) {
    if (!voltageMv || voltageMv <= 0) {
      return 'Battery SOC: not configured / N/A';
    }
    var label = chemistryLabel(chemistry);
    var soc = label ? voltageToPercent(voltageMv, chemistry) : null;
    if (soc == null) {
      return 'Battery SOC: ' + (voltageMv / 1000).toFixed(2) + ' V (chemistry unknown)';
    }
    return 'Battery SOC: ~' + soc + '% (' + (voltageMv / 1000).toFixed(2) + ' V, ' + label + ')';
  }

  var api = {
    CapacityEstimator: CapacityEstimator,
    voltageToPercent: voltageToPercent,
    chemistryLabel: chemistryLabel,
    formatSocLine: formatSocLine
  };

  global.OpenDisplayBattery = api;
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : this);
