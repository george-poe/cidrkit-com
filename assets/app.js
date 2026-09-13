/* Subnet 工具前端。
 *
 * 全部同步算：analyze 实测 0.042 ms/次，不需要 worker。
 * 唯一可能慢的是 summarize（50k 条 188 ms）和 split 的大列表，
 * 那两个都在按钮里做，并且渲染有上限——把 1600 万行塞进 DOM 是找死。
 */
(function () {
  "use strict";
  var E = self.CidrEngine;
  var RENDER_CAP = 2000;      // 列表渲染上限，超了就提示改用下载
  var DL_CAP = 200000;        // 下载上限，再大浏览器会当场没了

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
    });
  }

  /* ── 标签页 ─────────────────────────────────────────────────── */
  var TABS = ["calc", "sum", "split", "find"];
  function showTab(name) {
    TABS.forEach(function (t) {
      var p = $("panel-" + t), b = $("tab-" + t);
      if (p) p.hidden = (t !== name);
      if (b) b.setAttribute("aria-selected", t === name ? "true" : "false");
    });
    if (location.hash.slice(1) !== name) history.replaceState(null, "", "#" + name);
  }
  TABS.forEach(function (t) {
    var b = $("tab-" + t);
    if (b) b.addEventListener("click", function () { showTab(t); });
  });

  /* ── 1) 计算器 ──────────────────────────────────────────────── */
  var ROWS = [
    ["CIDR", "cidr"],
    ["Network address", "network_address"],
    ["Netmask", "netmask"],
    ["Wildcard mask", "wildcard"],
    ["Prefix length", "prefixlen"],
    ["Broadcast address", "broadcast"],
    ["First usable host", "first_host"],
    ["Last usable host", "last_host"],
    ["Total addresses", "num_addresses"],
    ["Usable hosts", "num_hosts"],
  ];
  var FLAGS = [
    ["Private / special-purpose (what Python's ipaddress calls private)", "is_private"],
    ["Loopback", "is_loopback"],
    ["Link-local", "is_link_local"],
    ["Multicast", "is_multicast"],
    ["Reserved", "is_reserved"],
    ["CGNAT (RFC 6598)", "is_cgnat"],
    ["Documentation (RFC 5737)", "is_documentation"],
    ["Benchmarking (RFC 2544)", "is_benchmarking"],
  ];

  function big(n) {
    var s = String(n);
    if (s.length <= 7) return s;
    var e = s.length - 1;
    return s.charAt(0) + "." + s.slice(1, 5) + " × 10^" + e;
  }

  function renderCalc() {
    var box = $("res"), txt = ($("net").value || "").trim();
    if (!txt) { box.innerHTML = '<p class="note">Type or paste a network above.</p>'; return; }
    var r = E.analyze(txt);
    if (!r.ok) {
      box.innerHTML = '<div class="errbox"><strong>Cannot parse that</strong>' +
        '<div class="err-msg">' + esc(r.error.message) + "</div></div>";
      return;
    }
    var bits = [];
    ROWS.forEach(function (pair) {
      var v = r[pair[1]];
      if (v === null || v === undefined) return;
      var shown = (pair[1] === "num_addresses" || pair[1] === "num_hosts") ? big(v) : v;
      // 只有真的被缩写过才补原文，否则小数字会显示成「32 32」
      var extra = (String(shown) !== String(v))
        ? ' <span class="dim">' + esc(String(v)) + "</span>" : "";
      bits.push("<tr><th>" + pair[0] + '</th><td><code>' + esc(String(shown)) +
                "</code>" + extra + "</td></tr>");
    });
    var on = [], off = [], unknown = [];
    FLAGS.forEach(function (pair) {
      var v = r[pair[1]];
      if (v === null || v === undefined) unknown.push(pair[0]);
      else if (v) on.push(pair[0]);
      else off.push(pair[0]);
    });
    if (on.length) {
      bits.push("<tr><th>Range class</th><td>" + esc(on.join(" · ")) + "</td></tr>");
    }
    if (unknown.length && r.version === 6) {
      bits.push('<tr><th>Range class</th><td><span class="dim">not reported for IPv6 — ' +
                "the registries are long and a partial copy would be worse than silence" +
                "</span></td></tr>");
    }
    if (r.host_bits_ignored) {
      bits.push('<tr><th>Note</th><td>Your host bits were outside the mask: ' +
                "<code>" + esc(r.host_bits_ignored_from) + "</code> is in " +
                "<code>" + esc(r.cidr) + "</code></td></tr>");
    }
    box.innerHTML = '<table class="kv">' + bits.join("") + "</table>" +
      '<div class="row"><button class="btn tiny" id="btn-copy-calc">Copy summary</button>' +
      '<span class="dim">version ' + r.version + " · parsed from " +
      esc(r.input_was) + "</span></div>";
    $("btn-copy-calc").addEventListener("click", function () {
      var lines = ROWS.map(function (pair) {
        return r[pair[1]] === null ? null : pair[0] + ": " + r[pair[1]];
      }).filter(Boolean);
      copy(lines.join("\n"), $("btn-copy-calc"));
    });
  }

  /* ── 2) 合并 ────────────────────────────────────────────────── */
  function renderSum() {
    var box = $("sum-res"), txt = ($("sum-in").value || "").trim();
    if (!txt) { box.innerHTML = '<p class="note">One CIDR per line.</p>'; return; }
    var list = txt.split(/[\s,;]+/).filter(Boolean);
    var t0 = performance.now();
    try {
      var out = E.summarize(list);
    } catch (e) {
      box.innerHTML = '<div class="errbox"><strong>Cannot parse that</strong><div class="err-msg">' +
        esc(e.message) + "</div></div>";
      return;
    }
    var ms = (performance.now() - t0).toFixed(1);
    box.innerHTML = '<p class="note">' + list.length + " blocks in → <strong>" + out.length +
      "</strong> out · " + ms + " ms · nothing uploaded</p>" +
      '<pre id="sum-out">' + esc(out.join("\n")) + "</pre>" +
      '<div class="row"><button class="btn tiny" id="btn-sum-copy">Copy</button>' +
      '<button class="btn tiny" id="btn-sum-dl">Download .txt</button></div>';
    $("btn-sum-copy").addEventListener("click", function () {
      copy(out.join("\n"), $("btn-sum-copy"));
    });
    $("btn-sum-dl").addEventListener("click", function () {
      download(out.join("\n") + "\n", "summarized-cidrs.txt");
    });
  }

  /* ── 3) 拆分 ────────────────────────────────────────────────── */
  function renderSplit() {
    var box = $("split-res");
    var net = ($("split-net").value || "").trim();
    var want = parseInt($("split-want").value, 10);
    if (!net) { box.innerHTML = '<p class="note">Give a network, e.g. 192.168.0.0/16.</p>'; return; }
    var r = E.analyze(net);
    if (!r.ok) {
      box.innerHTML = '<div class="errbox"><strong>Cannot parse that</strong><div class="err-msg">' +
        esc(r.error.message) + "</div></div>";
      return;
    }
    if (!(want > 1)) {
      box.innerHTML = '<div class="errbox"><strong>How many subnets?</strong>' +
        '<div class="err-msg">Enter 2 or more.</div></div>';
      return;
    }
    var diff = 0;
    while ((1 << diff) < want) diff++;
    var res = E.subnets(net, diff, RENDER_CAP);
    var total = BigInt(res.total);
    var shown = res.list.length;
    var head = "<p class=" + '"note"' + ">";
    head += "Each subnet: <code>/" + (r.prefixlen + diff) + "</code> (" +
      E.analyze(r.cidr.split("/")[0] + "/" + (r.prefixlen + diff)).num_hosts + " hosts). ";
    head += "That is <strong>" + total.toLocaleString() + "</strong> subnets — " +
      (want - (1 << diff) < 0 ? "rounded up from " + want + " to the next power of two. " : "") +
      (shown < Number(total) ? "Showing the first " + shown.toLocaleString() + "." : "") + "</p>";
    var pre = shown ? "<pre>" + esc(res.list.slice(0, RENDER_CAP).join("\n")) + "</pre>" : "";
    var dl = "";
    if (total <= BigInt(DL_CAP)) {
      dl = '<div class="row"><button class="btn tiny" id="btn-split-dl">Download all ' +
        total.toLocaleString() + " lines</button></div>";
    } else {
      dl = '<p class="note">Too many to hand you as a file (' + total.toLocaleString() +
        " lines). Split in stages, or use a script.</p>";
    }
    box.innerHTML = head + pre + dl;
    var b = $("btn-split-dl");
    if (b) b.addEventListener("click", function () {
      var all = E.subnets(net, diff, Number(total)).list;
      download(all.join("\n") + "\n", "subnets-" + r.cidr.replace("/", "-") + ".txt");
    });
  }

  /* ── 4) 地址在不在网段里 ─────────────────────────────────────── */
  function renderFind() {
    var box = $("find-res");
    var addr = ($("find-addr").value || "").trim();
    var cidr = ($("find-net").value || "").trim();
    if (!addr || !cidr) {
      box.innerHTML = '<p class="note">Both fields needed.</p>';
      return;
    }
    try {
      var inIt = E.contains(cidr, addr);
      box.innerHTML = "<p class=\"verdict " + (inIt ? "yes" : "no") + "\">" +
        esc(addr) + (inIt ? " is inside " : " is NOT inside ") + esc(cidr) + "</p>";
    } catch (e) {
      box.innerHTML = '<div class="errbox"><strong>Cannot parse that</strong><div class="err-msg">' +
        esc(e.message) + "</div></div>";
    }
  }

  /* ── 小工具 ─────────────────────────────────────────────────── */
  function flash(el, msg) {
    var old = el.textContent;
    el.textContent = msg;
    setTimeout(function () { el.textContent = old; }, 1100);
  }
  function copy(text, btn) {
    var done = function () { if (btn) flash(btn, "Copied"); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { legacy(text); done(); });
    } else { legacy(text); done(); }
  }
  function legacy(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand("copy"); } catch (e) { /* execCommand is deprecated; the flash still reports */ }
    document.body.removeChild(ta);
  }
  function download(text, name) {
    var a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 400);
  }

  /* 输入即时重算：0.042 ms/次，不需要防抖到秒级 */
  function live(id, fn) {
    var el = $(id);
    if (!el) return;
    el.addEventListener("input", function () {
      requestAnimationFrame(fn);
    });
  }
  live("net", renderCalc);
  live("sum-in", renderSum);
  live("split-net", renderSplit);
  live("split-want", renderSplit);
  live("find-addr", renderFind);
  live("find-net", renderFind);

  if ($("btn-clear")) $("btn-clear").addEventListener("click", function () {
    $("net").value = "";
    renderCalc();
    $("net").focus();
  });

  var initial = (location.hash || "").slice(1);
  if (TABS.indexOf(initial) < 0) initial = "calc";
  showTab(initial);
  renderCalc(); renderSum(); renderSplit(); renderFind();
})();
