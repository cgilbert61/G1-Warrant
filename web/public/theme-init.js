(function () {
  try {
    var stored = localStorage.getItem('g1_warrant_theme');
    var isDark =
      stored === 'dark' ||
      (!stored && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', isDark);
    document.documentElement.dataset.theme = isDark ? 'dark' : 'light';
    document.documentElement.style.colorScheme = isDark ? 'dark' : 'light';
  } catch (_err) {
    // Ignore storage errors in restricted webviews
  }
})();
