/* Subnet calculator engine — pure functions, no DOM dependency.
 *
 * one file, loaded from two places:
 *   · the page <script src="/assets/cidr.js">
 *   · test/index.html — answers checked against test/vectors.json
 *
 * why every calculation goes through BigInt instead of 32-bit integers:
 * the IPv6 address count is 2^128, and `2 ** (128 - 32)` turns straight into Infinity in a JS Number.
 * two numeric paths means two sets of bugs, so everything is BigInt, IPv4 included.
 *
 * semantics follow Python ipaddress (host bits outside the network are ignored, i.e. strict=False),
 * because users do paste 192.168.1.37/24, and an error tells them less than the network does.
 * the page states this outright; nothing is rewritten quietly.
 */
(function (root) {
  "use strict";

  var V4_BITS = 32n, V6_BITS = 128n;

  function CidrError(msg, detail) {
    this.name = "CidrError";
    this.message = msg;
    this.detail = detail || null;
  }
  CidrError.prototype = Object.create(Error.prototype);

  function fail(msg, detail) { throw new CidrError(msg, detail); }

  /* ── IPv4 text ───────────────────────────────────────────────────
   * four decimal parts, each 0-255, no leading zeros (the "00" in 0.1.2.3 is refused —
   * a leading zero is octal in POSIX, so accepting one in silence plants a mine).
   */
  function parseV4(s) {
    if (typeof s !== "string") fail("An IPv4 address must be text");
    var parts = s.trim().split(".");
    if (parts.length !== 4) {
      fail("An IPv4 address needs four dotted parts, e.g. 192.168.1.0. This has " + parts.length + " parts", {got: s});
    }
    var v = 0n;
    for (var i = 0; i < 4; i++) {
      var p = parts[i];
      if (!/^\d{1,3}$/.test(p)) {
        fail("Part " + (i + 1) + ", “" + p + "”, which is not a decimal number in 0-255", {octet: i, got: p});
      }
      if (p.length > 1 && p.charAt(0) === "0") {
        fail("Part " + (i + 1) + ", “" + p + "”, has a leading zero. " + "The standard reads a leading zero as octal, so this is refused. Write " + parseInt(p, 10) + " instead", {octet: i, got: p});
      }
      var n = parseInt(p, 10);
      if (n > 255) {
        fail("Part " + (i + 1) + " is " + n + ", which is above 255", {octet: i, got: p});
      }
      v = (v << 8n) | BigInt(n);
    }
    return v;
  }

  function formatV4(v) {
    v = ((v & ((1n << V4_BITS) - 1n)));
    return [24n, 16n, 8n, 0n].map(function (sh) {
      return Number((v >> sh) & 255n).toString();
    }).join(".");
  }

  /* ── IPv6 text ─────────────────────────────────────────────────
   * accepts :: compression and one optional trailing IPv4 (::ffff:1.2.3.4).
   * rules: at most one ::; exactly 8 groups without it; at most 7 explicit groups with it
   * (because :: has to stand for at least one group, otherwise the form is pointless — same as inet_pton).
   */
  function parseV6(s) {
    var t = s.trim();
    var tail = 0n, tailV4 = false;
    var dot = t.lastIndexOf(".");
    if (dot >= 0) {
      var before = t.slice(0, t.lastIndexOf(":") + 1);
      var maybe = t.slice(t.lastIndexOf(":") + 1);
      if (/^\d+\.\d+\.\d+\.\d+$/.test(maybe)) {
        tail = parseV4(maybe);
        tailV4 = true;
        // before looks like "::ffff:" — that trailing colon is the IPv4 separator,
        // leaving it in makes split() yield an empty string that is then judged invalid
        t = before.replace(/:+$/, "");
      } else {
        fail("IPv6 contains a fragment that is not an address: “" + t + "”", {got: s});
      }
    }

    var dcol = t.indexOf("::");
    var compress = dcol >= 0;
    if (compress && t.indexOf("::", dcol + 1) >= 0) {
      fail("IPv6 may contain only one “::”", {got: s});
    }

    function split(str) {
      if (str === "") return [];
      var out = str.split(":"), i;
      for (i = 0; i < out.length; i++) {
        if (!/^[0-9a-fA-F]{1,4}$/.test(out[i])) {
          fail("“" + out[i] + "” is not a valid IPv6 group (1-4 hex digits per group)", {got: str, at: i});
        }
      }
      return out;
    }

    var head, last;
    if (compress) {
      var hp = t.slice(0, dcol), tp = t.slice(dcol + 2);
      head = split(hp);
      last = split(tp);
      if (head.length + last.length > 7) {
        fail("The groups around “::” already fill 8 slots, so “::” has nothing left to stand for", {got: s});
      }
    } else {
      head = split(t);
      last = [];
    }

    // the explicit group count must treat the embedded IPv4 as 2 groups, otherwise "::ffff:1.2.3.4" fills 11,
    // and cutting it down with splice afterwards would cut from the head, i.e. lose the high bits
    var tailGroups = tailV4 ? 2 : 0;
    var explicit = head.length + last.length + tailGroups;
    if (compress) {
      if (explicit > 7) {
        fail("The groups around “::” add up to " + explicit + "" + (tailV4 ? " (the trailing IPv4 counts as two)" : "") + ", leaving no room for the zeros it stands for", {got: s});
      }
    } else if (explicit !== 8) {
      fail("IPv6 needs 8 groups; this has " + explicit + "", {got: s});
    }

    var groups = [];
    var i;
    for (i = 0; i < head.length; i++) groups.push(parseInt(head[i], 16));
    for (i = groups.length; i < 8 - last.length - tailGroups; i++) groups.push(0);
    for (i = 0; i < last.length; i++) groups.push(parseInt(last[i], 16));
    if (tailV4) {
      groups.push(Number((tail >> 16n) & 0xffffn));
      groups.push(Number(tail & 0xffffn));
    }
    var v = 0n;
    for (i = 0; i < 8; i++) v = (v << 16n) | BigInt(groups[i]);
    return v;
  }

  function formatV6(v) {
    var g = [], i;
    for (i = 0; i < 8; i++) {
      g.push(Number((v >> BigInt(16 * (7 - i))) & 0xffffn));
    }
    // compress the longest run of consecutive zeros (2 groups or more). a lone 0 is not compressed — that misuses ::,
    // and it matches what inet_pton and Python do.
    var bestS = -1, bestL = 0, runS = -1, runL = 0;
    for (i = 0; i < 8; i++) {
      if (g[i] === 0) {
        if (runS < 0) runS = i;
        runL++;
        if (runL > bestL) { bestL = runL; bestS = runS; }
      } else { runS = -1; runL = 0; }
    }
    if (bestL < 2) {
      return g.map(function (x) { return x.toString(16); }).join(":");
    }
    // it has to be head + "::" + tail assembled in two halves, not parts.join(":") —
    // with the zero run at the end join loses a colon, "2001:db8::" becomes "2001:db8:"
    var head = [], tail = [];
    for (i = 0; i < bestS; i++) head.push(g[i].toString(16));
    for (i = bestS + bestL; i < 8; i++) tail.push(g[i].toString(16));
    return head.join(":") + "::" + tail.join(":");
  }

  function formatAddr(v, ver) {
    return ver === 4 ? formatV4(v) : formatV6(v);
  }

  function bitsOf(ver) { return ver === 4 ? V4_BITS : V6_BITS; }

  /* ── Masks ────────────────────────────────────────────────────────
   * a netmask must be one run of 1s then one run of 0s; a hostmask is the reverse.
   * both are accepted (Cisco people write ACLs with a wildcard), but they must be told apart:
   * 255.255.0.255 is neither — it must error out, not be guessed as /16 or /24.
   */
  function netmaskLen(m, bits) {
    // netmask = a run of 1s at the top plus a run of 0s below, and it must fill the whole width.
    // note bits is a BigInt: comparing n+ones as a Number against it with !== is always true,
    // so every dotted mask came out illegal. convert to Number before comparing.
    var total = Number(bits);
    var n = 0, x = m;
    while (x > 0n && (x & 1n) === 0n) { x >>= 1n; n++; }     // trailing 0s
    var ones = 0, y = x;
    while (y > 0n && (y & 1n) === 1n) { y >>= 1n; ones++; }   // the 1s right after it
    if (y !== 0n || n + ones !== total) return -1;
    return ones;                        // /0 arrives here as 0, not -1
  }

  function hostmaskLen(m, bits) {
    // hostmask = a run of 1s at the bottom, 0s everywhere else
    var c = 0, x = m;
    while (x > 0n && (x & 1n) === 1n) { x >>= 1n; c++; }
    if (x !== 0n) return -1;
    return Number(bits) - c;
  }

  function prefixFromMaskInt(m, bits) {
    var p = netmaskLen(m, bits);
    if (p >= 0) return { prefixlen: p, as: "netmask" };
    var h = hostmaskLen(m, bits);
    if (h >= 0) return { prefixlen: h, as: "hostmask" };
    return null;
  }

  function maskFromPrefix(p, bits) {
    if (p === 0) return 0n;
    return ~((1n << BigInt(bits) - BigInt(p)) - 1n) & ((1n << BigInt(bits)) - 1n);
  }

  /* ── Entry: collapse what users type into {version, network, prefixlen} ──
   * accepts:
   *   10.0.0.0/8            prefix
   *   10.0.0.0 255.0.0.0    dotted mask (space or / both fine)
   *   10.0.0.0 0.255.255.255  wildcard mask
   *   10.0.0.0 - 10.0.0.255  start - end range (must be exactly one valid network)
   *   10.0.0.0              bare address → /32 (v6 → /128)
   */
  function parse(text) {
    var t = String(text == null ? "" : text).trim();
    if (!t) fail("Nothing to work with. Give it a CIDR such as 10.0.0.0/8, an address with a mask, or a start - end range");

    var version = t.indexOf(":") >= 0 ? 6 : 4;

    // a start - end range has to be recognised first. it carries a space, so a moment later the
    // generic address + mask split below takes it — both ends of a range are full addresses,
    // so the split yields address + "- 144.54.31.255" and the error says part 1 is not a decimal number.
    var rg = t.match(/^(\S+)\s*(-|\u2013|to)\s*(\S+)$/i);
    if (rg) {
      var loS = rg[1], hiS = rg[3];
      var rver = (loS.indexOf(":") >= 0 || hiS.indexOf(":") >= 0) ? 6 : 4;
      var rbits = bitsOf(rver);
      var lo = rver === 4 ? parseV4(loS) : parseV6(loS);
      var hi = rver === 4 ? parseV4(hiS) : parseV6(hiS);
      if (hi < lo) fail("The range is backwards: " + loS + " is above " + hiS + "");
      var size = hi - lo + 1n;
      if ((size & (size - 1n)) !== 0n) {
        // never return a guessed covering prefix: that loosens the ACL on the users behalf. but it can put
        // the smallest block that covers it into the error text and let the user decide.
        var cp = Number(rbits) - bitLength(size);
        if (cp < 0) cp = 0;
        for (;;) {
          var candSize = 1n << (rbits - BigInt(cp));
          if (((lo & maskFromPrefix(cp, rbits)) + candSize - 1n) >= hi || cp === 0) break;
          cp -= 1;
        }
        var coverNet = lo & maskFromPrefix(cp, rbits);
        var coverSize = 1n << (rbits - BigInt(cp));
        fail("A start - end range must be exactly one aligned power-of-two block. This spans " +
             size + " addresses. The smallest block that covers it is " +
             formatAddr(coverNet, rver) + "/" + cp + ", which would add " +
             (coverSize - size) + " addresses you did not ask for — so nothing was returned. " +
             "To describe this range exactly, list the blocks in the Collapse tab.",
             {got: loS, covering: formatAddr(coverNet, rver) + "/" + cp});
      }
      // bitLength(2**n) is n+1, not n: 256 in binary is a 1 followed by 8 zeros.
      var rp = Number(rbits) - (bitLength(size) - 1);
      var netInt = lo & maskFromPrefix(rp, rbits);
      if (netInt !== lo) {
        fail("The range start " + loS + " is not the network address of this block — aligned it would be " + formatAddr(netInt, rver) + "/" + rp + "", {got: loS});
      }
      var rbc = netInt | (~maskFromPrefix(rp, rbits) & ((1n << rbits) - 1n));
      if (rbc !== hi) fail("The range end " + hiS + " is not the broadcast address of this block — it should be " + formatAddr(rbc, rver) + "", {got: hiS});
      return { version: rver, network: netInt, prefixlen: rp, inputWas: "range" };
    }

    var m = t.match(/^(.*?)(?:\s*\/\s*|\s+)([^\/]+)$/);
    var addrPart = t, second = null;
    if (m && m[1].trim()) { addrPart = m[1].trim(); second = m[2].trim(); }

    var addr = version === 4 ? parseV4(addrPart) : parseV6(addrPart);
    var bits = bitsOf(version);

    if (second === null) {
      return { version: version, network: addr, prefixlen: Number(bits),
               inputWas: "bare" };
    }

    var prefix = null, as = "prefix";
    if (/^\d+$/.test(second)) {
      prefix = parseInt(second, 10);
      if (prefix > Number(bits)) {
        fail("/" + prefix + " is past the limit: the longest IPv" + version + " prefix is /" + Number(bits));
      }
      as = "prefix";
    } else {
      var maskInt = version === 4 ? parseV4(second) : parseV6(second);
      var got = prefixFromMaskInt(maskInt, bits);
      if (!got) {
        fail(second + " is neither a valid netmask (ones as a single run at the top) nor a valid wildcard mask" + " (ones as a single run at the bottom), so there is no prefix to derive from it", {got: second});
      }
      prefix = got.prefixlen; as = got.as;
    }

    var mask = maskFromPrefix(prefix, bits);
    var network = addr & mask;
    return {
      version: version, network: network, prefixlen: prefix,
      inputWas: as,
      // host bits were cleared — the page has to say so instead of pretending the input was a network address
      hostBitsIgnored: network !== addr,
      originalHost: addr
    };
  }

  function bitLength(n) {
    var b = 0;
    while (n > 0n) { n >>= 1n; b++; }
    return b;
  }

  /* ── Summarize ────────────────────────────────────────────────────── */
  function inNetwork(addr, net, prefixlen, bits) {
    return (addr & maskFromPrefix(prefixlen, bits)) === net;
  }

  var V4_PRIVATE = ["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
                    "172.16.0.0/12", "192.0.0.0/29", "192.0.0.170/31",
                    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
                    "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
                    "255.255.255.255/32"];
  /* CGNAT (RFC 6598). Python is_private does not cover it, so it cannot go into the table above —
     the baseline is Python. but "is this carrier NAT space" is useful to users, so it gets its own field. */
  var V4_CGNAT = ["100.64.0.0/10"];
  var V4_DOC = ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"];
  var V4_BENCHMARK = ["198.18.0.0/15"];
  var V4_RESERVED = ["240.0.0.0/4", "255.255.255.255/32"];
  var V4_MULTICAST = ["224.0.0.0/4"];
  var V4_LOOPBACK = ["127.0.0.0/8"];
  var V4_LINK_LOCAL = ["169.254.0.0/16"];

  function within(addr, prefixlen, list, bits) {
    for (var i = 0; i < list.length; i++) {
      var e = list[i].split("/");
      var n = parseV4(e[0]), p = parseInt(e[1], 10);
      if (prefixlen >= p && inNetwork(addr, n, p, bits)) return true;
    }
    return false;
  }

  function flags(network, prefixlen, version) {
    if (version !== 4) {
      // no guessing: the IPv6 classification table is long (Python lists dozens), a partial copy is worse than silence
      return { is_private: null, is_loopback: null, is_link_local: null,
               is_multicast: null, is_reserved: null, is_cgnat: null,
               is_documentation: null, is_benchmarking: null };
    }
    var bits = V4_BITS;
    return {
      is_private: within(network, prefixlen, V4_PRIVATE, bits),
      is_loopback: within(network, prefixlen, V4_LOOPBACK, bits),
      is_link_local: within(network, prefixlen, V4_LINK_LOCAL, bits),
      is_multicast: within(network, prefixlen, V4_MULTICAST, bits),
      is_reserved: within(network, prefixlen, V4_RESERVED, bits),
      is_cgnat: within(network, prefixlen, V4_CGNAT, bits),
      is_documentation: within(network, prefixlen, V4_DOC, bits),
      is_benchmarking: within(network, prefixlen, V4_BENCHMARK, bits)
    };
  }

  function analyze(text) {
    var p;
    try { p = parse(text); }
    catch (e) {
      if (e instanceof CidrError) return { ok: false, error: { message: e.message, detail: e.detail } };
      throw e;
    }
    var bits = bitsOf(p.version);
    var mask = maskFromPrefix(p.prefixlen, bits);
    var bcast = p.network | (~mask & ((1n << bits) - 1n));
    var total = 1n << (bits - BigInt(p.prefixlen));

    // which addresses to reserve is not a minus-two rule: v4 drops first and last (neither for /31 nor /32),
    // v6 drops only the subnet-router anycast (first address) — v6 has no broadcast, the last address is an ordinary
    // usable address; /127 and /128 drop nothing. the reference is Python ipaddress; a large network
    // cannot be materialised, so this rule is matched in make_vectors.py on the small prefixes that can be.
    var isSpecial = (bcast - p.network) <= 1n;
    var first = isSpecial ? p.network : p.network + 1n;
    var last = (p.version === 6 || isSpecial) ? bcast : bcast - 1n;
    var hosts = last >= first ? (last - first + 1n) : 0n;

    var out = {
      ok: true,
      cidr: formatAddr(p.network, p.version) + "/" + p.prefixlen,
      version: p.version,
      network_address: formatAddr(p.network, p.version),
      netmask: p.version === 4 ? formatV4(mask) : null,
      wildcard: p.version === 4 ? formatV4(~mask & ((1n << bits) - 1n)) : null,
      broadcast: p.version === 4 ? formatAddr(bcast, 4) : null,
      prefixlen: p.prefixlen,
      num_addresses: total.toString(),
      num_hosts: hosts.toString(),
      first_host: hosts > 0n ? formatAddr(first, p.version) : null,
      last_host: hosts > 0n ? formatAddr(last, p.version) : null,
      input_was: p.inputWas,
      host_bits_ignored: !!p.hostBitsIgnored,
      host_bits_ignored_from: p.hostBitsIgnored
        ? formatAddr(p.originalHost, p.version) : null
    };
    var f = flags(p.network, p.prefixlen, p.version);
    for (var k in f) out[k] = f[k];
    return out;
  }

  /* ── Supernet summarize: equals Python collapse_addresses ─────────────
   *
   * do not write it as pairwise containment checks — that is O(n^2) and dies at 10k entries
   * (the first version did exactly that: 50k entries took the tab down).
   * the right shape is a sorted scan:
   *   1. sort once by network address ascending, then by prefix ascending (wider first) on ties
   *   2. if a block has a container, it must be the last kept block on the scan line —
   *      because everything in between lies inside the same parent block and was swallowed already.
   *      so one linear pass is enough and the O(n log n) is all sorting.
   *   3. merge same-size siblings, repeat to a fixed point. each round drops at least one block,
   *      the round count is bounded by the width (32 / 128), so it stays O(rounds × n log n).
   */
  function summarize(list) {
    if (!list || !list.length) return [];
    var items = [], i, r;
    for (i = 0; i < list.length; i++) {
      r = parse(list[i]);
      items.push({ v: r.version, n: r.network, p: r.prefixlen });
    }
    var ver = items[0].v;
    for (i = 1; i < items.length; i++) {
      if (items[i].v !== ver) {
        throw new CidrError("Cannot collapse IPv4 and IPv6 in the same run");
      }
    }
    var bits = bitsOf(ver);

    items.sort(function (a, b) { return cmpBig(a.n, b.n) || a.p - b.p; });

    // 1) drop anything fully contained in the last kept block
    var kept = [];
    for (i = 0; i < items.length; i++) {
      if (kept.length) {
        var k = kept[kept.length - 1];
        if (items[i].p >= k.p && inNetwork(items[i].n, k.n, k.p, bits)) continue;
      }
      kept.push(items[i]);
    }

    // 2) merge adjacent same-size sibling blocks
    var changed = true;
    while (changed) {
      changed = false;
      kept.sort(function (a, b) { return cmpBig(a.n, b.n) || a.p - b.p; });
      var merged = [], j = 0;
      while (j < kept.length) {
        var a = kept[j], b = kept[j + 1];
        if (b && a.p === b.p && a.p > 0) {
          var size = 1n << (bits - BigInt(a.p));
          if (b.n - a.n === size && (a.n % (size * 2n)) === 0n) {
            merged.push({ v: a.v, n: a.n, p: a.p - 1 });
            j += 2; changed = true; continue;
          }
        }
        merged.push(a); j++;
      }
      kept = merged;
    }

    // 3) merging can create new containment (a parent swallowed a fragment next door), so scan again
    kept.sort(function (x, y) { return cmpBig(x.n, y.n) || x.p - y.p; });
    var fin = [];
    for (i = 0; i < kept.length; i++) {
      if (fin.length) {
        var f = fin[fin.length - 1];
        if (kept[i].p >= f.p && inNetwork(kept[i].n, f.n, f.p, bits)) continue;
      }
      fin.push(kept[i]);
    }

    return fin.map(function (x) { return formatAddr(x.n, x.v) + "/" + x.p; });
  }

  function cmpBig(a, b) { return a < b ? -1 : (a > b ? 1 : 0); }

  /* ── Split: cut diff levels, return the first cap entries + the total ───────────────────── */
  function subnets(text, diff, cap) {
    var r = parse(text);
    var bits = bitsOf(r.version);
    var newP = r.prefixlen + diff;
    if (newP > Number(bits)) {
      throw new CidrError("Splitting " + diff + " more levels reaches /" + newP + ", past the IPv" + r.version + " limit of /" + Number(bits));
    }
    var count = 1n << BigInt(diff);
    var step = 1n << (bits - BigInt(newP));
    var out = [], n = r.network, limit = cap == null ? 1024 : cap;
    for (var i = 0n; i < count && i < BigInt(limit); i++) {
      out.push(formatAddr(n, r.version) + "/" + newP);
      n += step;
    }
    return { total: count.toString(), list: out };
  }

  /* ── Containment ─────────────────────────────────────────────────── */
  function contains(cidrText, addrText) {
    var net = parse(cidrText);
    var a = String(addrText).trim();
    var ver = a.indexOf(":") >= 0 ? 6 : 4;
    if (ver !== net.version) {
      throw new CidrError("Version mismatch: " + cidrText + " is IPv" + net.version + " but " + addrText + " is IPv" + ver);
    }
    var av = ver === 4 ? parseV4(a) : parseV6(a);
    return inNetwork(av, net.network, net.prefixlen, bitsOf(ver));
  }

/* FB-BLOCK:BEGIN */
  /* ── Feedback prefill ───────────────────────────────────────────────
     A visitor hitting an error gets one link that opens a note *they* send.
     Nothing is sent by the page itself: no fetch, no beacon, no request until
     a click happens. What the prefill carries is deliberately small — the page
     path, the byte length, the timing, and the message the tool printed. The
     document is never carried whole and no field exceeds FB_FIELD_CAP, but the
     honest wording matters: some error messages quote a short fragment of the
     input (that is what makes them useful), which is why the note is always
     shown to the visitor for editing before anything is sent, and why
     /privacy/ says exactly that instead of claiming a leak-proof channel.
     The caps are asserted in test/index.html with a canary string, and the
     call sites in app.js are audited by tools/feedback.py at build time. */
  var FB_KEYS = ["tool", "page", "bytes", "ms", "error", "line", "column",
                 "notice", "indent", "nodes", "host", "bits"];
  var FB_FIELD_CAP = 120;
  var FB_URL_CAP = 1800;

  function fbClip(v) {
    if (v === null || v === undefined || v === "") return "";
    /* Numbers are truncated to an integer and printed without an exponent, on both
       sides of the parity check. JS String(1e21) is "1e+21" while Python's is 22 raw
       digits, and the parity fixture caught that on its first run — so the contract is
       "integers, decimal notation", not "whatever the language's default gives". */
    if (typeof v === "number") {
      if (!isFinite(v)) return "";
      var t = Math.trunc(v);
      /* toFixed(0) is NOT decimal notation at magnitude: past 1e21 the spec says it
         just returns ToString, which flips to "1e+21". BigInt is the exact-integer
         path, and 1e300 stays decimal that way too — matching Python's int(). */
      v = (typeof BigInt!== "undefined" && Math.abs(t) >= 1e21)? BigInt(t).toString(): t.toFixed(0);
    }
    var s = String(v).replace(/\s+/g, " ").trim();
    if (!s) return "";
    return s.length > FB_FIELD_CAP? s.slice(0, FB_FIELD_CAP - 1): s;
  }

  function fbLabel(k) {
    return k === "ms"? "Milliseconds": k.charAt(0).toUpperCase() + k.slice(1);
  }

  /** Build the address a feedback note opens at. "" when no channel is set.
      `at` exists for the parity fixture only (tools/fb_parity.py) — production
      call sites never pass it, so the page path is always the real one. */
  function reportURL(extra, at) {
    var cfg = root.SITE_FEEDBACK;
    if (!cfg) return "";
    extra = extra || {};
    var here = (at !== undefined && at !== null)? String(at)
      : ((typeof location!== "undefined" && location.pathname)? location.pathname: "/");
    var lines = ["Page: " + fbClip(here)];
    if (cfg.built) lines.push("Build: " + cfg.built);   // stale-cache triage: which bundle did they see?
    for (var k in extra) {
      if (FB_KEYS.indexOf(k) < 0) continue;
      var v = fbClip(extra[k]);
      if (v) lines.push(fbLabel(k) + ": " + v);
    }
    lines.push("— written by a visitor; the page does not attach the document " +
               "being worked on. Paste a minimal sample yourself only if you " +
               "are fine with it becoming public.");
    var subject = "[" + (cfg.site || "feedback") + "] " + fbClip(here);
    var err = fbClip(extra.error || "");
    if (err) subject += " — " + err.slice(0, 60);

    function assemble(bodyText) {
      if (cfg.repo) {
        return "https://github.com/" + cfg.repo + "/issues/new?title=" +
               encodeURIComponent(subject) + "&body=" + encodeURIComponent(bodyText);
      }
      if (cfg.mail) {
        return "mailto:" + cfg.mail + "?subject=" + encodeURIComponent(subject) +
               "&body=" + encodeURIComponent(bodyText.replace(/\n/g, "\r\n"));
      }
      return "";
    }

    var body = lines.join("\n");
    var url = assemble(body);
    // Overlong: drop diagnostics from the middle, keeping the first line (the page)
    // and the last (the note that says nothing was attached).
    while (url.length > FB_URL_CAP && lines.length > 2) {
      lines.splice(lines.length - 2, 1);
      body = lines.join("\n");
      url = assemble(body);
    }
    // Still over: cut the raw text before encoding it. Slicing the finished URL can
    // split a percent-escape, and a stray "%4" shows up in the report as a broken page.
    while (url.length > FB_URL_CAP && body.length > 24) {
      body = body.slice(0, Math.floor(body.length * (FB_URL_CAP - 40) / url.length)) + " ...";
      url = assemble(body);
    }
    if (url.length > FB_URL_CAP) url = assemble("Details trimmed: the note was too long to send.");
    return url;
  }
/* FB-BLOCK:END */

  root.CidrEngine = {
    analyze: analyze,
    parse: parse,
    summarize: summarize,
    subnets: subnets,
    contains: contains,
    formatV4: formatV4,
    parseV4: parseV4,
    formatV6: formatV6,
    parseV6: parseV6,
    CidrError: CidrError,
    reportURL: reportURL,
    fbClip: fbClip,
    FB_KEYS: FB_KEYS,
    FB_FIELD_CAP: FB_FIELD_CAP,
    FB_URL_CAP: FB_URL_CAP
  };
})(typeof self !== "undefined" ? self : this);
