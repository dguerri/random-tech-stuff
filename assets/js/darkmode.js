function enableDarkMode() {
  DarkReader.setFetchMethod(window.fetch)
  DarkReader.enable();
  localStorage.setItem('dark-mode', 'true');

  document.getElementById('dark-mode-button').innerHTML = '<i>light</i>';
}

function disableDarkMode() {
  DarkReader.disable();
  localStorage.setItem('dark-mode', 'false');

  document.getElementById('dark-mode-button').innerHTML = '<i>dark</i>';
}

function darkmode() {
  let enabled = localStorage.getItem('dark-mode')

  if (enabled === null) {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      enableDarkMode();
    }
  } else if (enabled === 'true') {
    enableDarkMode()
  }

  if (localStorage.getItem('dark-mode') === 'false') {
    enableDarkMode();
  } else {
    disableDarkMode();
  }
}

function darkmodeOnStart() {
  if (localStorage.getItem('dark-mode') === 'true') {
    enableDarkMode();
  } else {
    disableDarkMode();
  }
}
