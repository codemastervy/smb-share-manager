// Upload handler: streams each selected file as a raw PUT body (no multipart spooling).
// Existing files are never replaced; the server picks "name (1).ext" on conflict.
(function () {
  "use strict";

  function csrfToken() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.getAttribute("content") : "";
  }

  async function uploadOne(form, file) {
    var dir = form.getAttribute("data-dir");
    var url = "/browse/upload?dir=" + encodeURIComponent(dir) + "&name=" + encodeURIComponent(file.name);
    var resp = await fetch(url, {
      method: "PUT",
      body: file,
      credentials: "same-origin",
      headers: { "X-CSRF-Token": csrfToken(), "Content-Type": "application/octet-stream" },
    });
    var data = {};
    try { data = await resp.json(); } catch (e) { /* ignore */ }
    if (!resp.ok) {
      throw new Error(file.name + ": " + (data.error || ("HTTP " + resp.status)));
    }
    return data.name;
  }

  document.addEventListener("submit", async function (ev) {
    var form = ev.target;
    if (!form.classList || !form.classList.contains("upload")) { return; }
    ev.preventDefault();
    var input = form.querySelector('input[type="file"]');
    var status = form.querySelector(".upload-status");
    var maxBytes = parseInt(form.getAttribute("data-max-mb"), 10) * 1024 * 1024;
    var errors = [];
    var saved = [];
    for (var i = 0; i < input.files.length; i++) {
      var f = input.files[i];
      if (f.size > maxBytes) { errors.push(f.name + ": larger than the upload limit"); continue; }
      status.textContent = "Uploading " + f.name + "...";
      try { saved.push(await uploadOne(form, f)); } catch (e) { errors.push(e.message); }
    }
    status.textContent = (saved.length ? "Uploaded: " + saved.join(", ") + ". " : "") +
      (errors.length ? "Failed: " + errors.join("; ") : "");
    if (saved.length && !errors.length) { window.location.reload(); }
  }, true);
})();
