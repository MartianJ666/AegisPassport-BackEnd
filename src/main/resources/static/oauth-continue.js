// The destination is the server-validated authorization result rendered in the page.
(() => {
  const link = document.getElementById('oauth-continue')
  if (link) window.location.replace(link.href)
})()
