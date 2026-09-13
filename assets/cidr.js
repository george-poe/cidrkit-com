/* Subnet 计算引擎 —— 纯函数，无 DOM 依赖。
 *
 * 同一份文件被两处加载：
 *   · 页面 <script src="/assets/cidr.js">
 *   · test/index.html —— 拿 test/vectors.json 对答案
 *
 * 为什么所有算术都走 BigInt 而不是 32 位整数：
 * IPv6 的地址数是 2^128，`2 ** (128 - 32)` 在 JS Number 里直接变 Infinity。
 * 用两套数字路径就会有两套 bug，所以统一 BigInt，IPv4 也一样走。
 *
 * 语义对齐 Python 的 ipaddress（网络位以外的主机位被忽略，即 strict=False），
 * 因为用户就是会粘贴 192.168.1.37/24 这种，报错不如告诉他网段是什么。
 * 这一点在页面上明说了，不偷偷改。
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

  /* ── IPv4 文本 ───────────────────────────────────────────────────
   * 四条十进制、每条 0-255、不许前导零（0.1.2.3 里的 "00" 会被拒——
   * 前导零在 POSIX 里是八进制，静默接受等于埋雷）。
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

  /* ── IPv6 文本 ─────────────────────────────────────────────────
   * 支持 :: 缩写、一个可选的末尾 IPv4（::ffff:1.2.3.4）。
   * 规则：至多一个 ::；不含 :: 时正好 8 组；含 :: 时显式组数 ≤ 7
   * （因为 :: 至少要代替一组，否则写法无意义 —— 和 inet_pton 一致）。
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
        // before 形如 "::ffff:" —— 那个收尾冒号是 IPv4 的分隔符，
        // 留着会让 split() 切出一个空串然后被判非法
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

    // 显式组数要把内嵌 IPv4 算成 2 组，否则 "::ffff:1.2.3.4" 会填出 11 组，
    // 再靠 splice 硬砍——砍掉的是 head，等于把高位丢了
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
    // 找最长的连续零段（≥2 组）来压缩。单组 0 不压——那是 :: 的误用，
    // 也和 inet_pton / Python 的行为一致。
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
    // 必须是 head + "::" + tail 两段拼，不能拿 parts.join(":") 凑——
    // 零段在末尾时 join 会少一个冒号，"2001:db8::" 变成 "2001:db8:"
    var head = [], tail = [];
    for (i = 0; i < bestS; i++) head.push(g[i].toString(16));
    for (i = bestS + bestL; i < 8; i++) tail.push(g[i].toString(16));
    return head.join(":") + "::" + tail.join(":");
  }

  function formatAddr(v, ver) {
    return ver === 4 ? formatV4(v) : formatV6(v);
  }

  function bitsOf(ver) { return ver === 4 ? V4_BITS : V6_BITS; }

  /* ── 掩码 ────────────────────────────────────────────────────────
   * netmask 必须是一串 1 紧跟一串 0；hostmask 反过来。
   * 两种都接受（Cisco 的人写 ACL 用的是 wildcard），但要能分辨：
   * 255.255.0.255 两个都不是 —— 必须报错，不能猜成 /16 或 /24。
   */
  function netmaskLen(m, bits) {
    // netmask = 高位一串 1 + 低位一串 0，且必须铺满整宽度。
    // 注意 bits 是 BigInt：拿 Number 的 n+ones 去 !== 它会恒真，
    // 于是所有点分掩码都被判成非法。先转成 Number 再比。
    var total = Number(bits);
    var n = 0, x = m;
    while (x > 0n && (x & 1n) === 0n) { x >>= 1n; n++; }     // 尾部 0
    var ones = 0, y = x;
    while (y > 0n && (y & 1n) === 1n) { y >>= 1n; ones++; }   // 紧接着的 1
    if (y !== 0n || n + ones !== total) return -1;
    return ones;                        // /0 走到这里是 0，不是 -1
  }

  function hostmaskLen(m, bits) {
    // hostmask = 低位一串 1，其余全 0
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

  /* ── 入口：把用户会写的各种形式收敛成 {version, network, prefixlen} ──
   * 接受：
   *   10.0.0.0/8            前缀
   *   10.0.0.0 255.0.0.0    点分掩码（空格或 / 都行）
   *   10.0.0.0 0.255.255.255  通配符掩码
   *   10.0.0.0 - 10.0.0.255  起止区间（必须正好是一个合法网段）
   *   10.0.0.0              裸地址 → /32（v6 → /128）
   */
  function parse(text) {
    var t = String(text == null ? "" : text).trim();
    if (!t) fail("Nothing to work with. Give it a CIDR such as 10.0.0.0/8, an address with a mask, or a start - end range");

    var version = t.indexOf(":") >= 0 ? 6 : 4;

    // 起止区间必须先认。它内部本来就带空格，晚一步就被下面
    // 「地址 + 掩码」那条通用切分抢走了——区间两侧各是一个完整地址，
    // 切出来变成 地址 + "- 144.54.31.255"，然后报"Part 1 段不是十进制"。
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
        // 不给猜一个覆盖前缀就返回：那等于替用户放宽 ACL。但可以把
        // 「最小能装下它的块」算出来写在错语里，让他自己决定要不要。
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
      // bitLength(2**n) 是 n+1，不是 n：256 的二进制是 1 跟 8 个 0。
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
      // 主机位被抹掉了 —— 页面上要能说出来，不能假装用户写的就是网络地址
      hostBitsIgnored: network !== addr,
      originalHost: addr
    };
  }

  function bitLength(n) {
    var b = 0;
    while (n > 0n) { n >>= 1n; b++; }
    return b;
  }

  /* ── 汇总 ────────────────────────────────────────────────────── */
  function inNetwork(addr, net, prefixlen, bits) {
    return (addr & maskFromPrefix(prefixlen, bits)) === net;
  }

  var V4_PRIVATE = ["0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
                    "172.16.0.0/12", "192.0.0.0/29", "192.0.0.170/31",
                    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
                    "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
                    "255.255.255.255/32"];
  /* CGNAT（RFC 6598）。Python 的 is_private 不含它，所以不能塞进上面那张表——
     比对基准就是 Python。但"这段是不是运营商 NAT 内网"对用户有用，单列一个字段。 */
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
      // 不猜：IPv6 的分类表很长（Python 那份有几十条），抄一半比不抄更坏
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

    // 保留哪些地址不是一个「减二」能概括的：v4 去头去尾（/31 与 /32 都不去），
    // v6 只去 subnet-router anycast（首址）——v6 没有 broadcast，尾址是普通
    // 可用地址；/127 与 /128 一个都不去。基准是 Python ipaddress；大网段
    // 不能物化，所以这条规则在 make_vectors.py 里先在可物化的小前缀上对过。
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

  /* ── 超网汇总：等价于 Python 的 collapse_addresses ─────────────
   *
   * 别照着"两两比较谁包含谁"写——那是 O(n^2)，10k 条就废了
   * （第一版就是，实测 50k 条直接把标签页跑没了）。
   * 正解是排序扫描：
   *   1. 按网络地址升序、同地址按前缀升序（宽的在前）排一次
   *   2. 任何块的包含者若存在，必然是扫描线上"上一个保留块"——
   *      因为中间那些一定也落在同一个父块里，早就被吃掉了。
   *      所以一遍线性扫描就够，O(n log n) 全在排序。
   *   3. 合并同尺寸兄弟块，反复到不动点。每轮至少少一个块，
   *      轮数上界就是位宽（32 / 128），所以是 O(轮数 × n log n)。
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

    // 1) 丢掉被上一个保留块完全包含的
    var kept = [];
    for (i = 0; i < items.length; i++) {
      if (kept.length) {
        var k = kept[kept.length - 1];
        if (items[i].p >= k.p && inNetwork(items[i].n, k.n, k.p, bits)) continue;
      }
      kept.push(items[i]);
    }

    // 2) 合并相邻的等尺寸兄弟块
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

    // 3) 合并可能造出新的包含关系（父块吃掉了旁边某个碎块），再扫一遍
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

  /* ── 拆分：切 diff 层，返回前 cap 条 + 总数 ───────────────────── */
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

  /* ── 包含判断 ─────────────────────────────────────────────────── */
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
    CidrError: CidrError
  };
})(typeof self !== "undefined" ? self : this);
