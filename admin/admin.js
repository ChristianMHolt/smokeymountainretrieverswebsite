// /admin/admin.js
// Shared helper for admin static pages (calls backend /api/*)
window.smrAdmin = (() => {
  const BASE = "/api/admin";

  async function jsonOrThrow(res) {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data?.error ? String(data.error) : `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  function headers() {
    // Required by backend for admin write actions (light CSRF mitigation)
    return { "X-Requested-With": "smr-admin" };
  }

  async function me() {
    const res = await fetch(`${BASE}/me`, { credentials: "include" });
    return jsonOrThrow(res);
  }

  async function getCodes(limit = 500) {
    const res = await fetch(`${BASE}/codes?limit=${encodeURIComponent(limit)}`, {
      credentials: "include",
      headers: headers()
    });
    return jsonOrThrow(res);
  }

  async function addCodes(codesText) {
    const fd = new FormData();
    fd.set("codes", codesText);

    const res = await fetch(`${BASE}/codes/add`, {
      method: "POST",
      credentials: "include",
      headers: headers(),
      body: fd
    });
    return jsonOrThrow(res);
  }

  async function deleteCode(code) {
    const fd = new FormData();
    fd.set("code", code);

    const res = await fetch(`${BASE}/codes/delete`, {
      method: "POST",
      credentials: "include",
      headers: headers(),
      body: fd
    });
    return jsonOrThrow(res);
  }

  async function logout() {
    const res = await fetch(`${BASE}/logout`, {
      method: "POST",
      credentials: "include",
      headers: headers()
    });
    return jsonOrThrow(res);
  }

  return { me, getCodes, addCodes, deleteCode, logout };
})();
