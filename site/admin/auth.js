(() => {
  const API_BASE = "https://api.rallyattheridge.org";
  window.ADMIN_API_BASE = API_BASE;

  const loginPath = "/admin/login.html";
  const path = window.location.pathname;
  if (path === loginPath) return;

  const html = document.documentElement;
  html.style.visibility = "hidden";

  fetch(`${API_BASE}/api/admin/session`, { credentials: "include" })
    .then((res) => {
      if (res.status === 401) {
        const next = encodeURIComponent(window.location.pathname + window.location.search);
        window.location.href = `${loginPath}?next=${next}`;
        return;
      }
      html.style.visibility = "";
    })
    .catch(() => {
      const next = encodeURIComponent(window.location.pathname + window.location.search);
      window.location.href = `${loginPath}?next=${next}`;
    });
})();
