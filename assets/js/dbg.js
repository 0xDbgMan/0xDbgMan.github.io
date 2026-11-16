(function () {
  var $ = function (id) { return document.getElementById(id); };

  // Old Chirpy theme registered a service worker; remove it so visitors get the new design.
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then(function (rs) { rs.forEach(function (r) { r.unregister(); }); }).catch(function () {});
  }

  // mobile menu
  var burger = $('burger'), nav = $('site-nav');
  if (burger && nav) burger.addEventListener('click', function () { nav.classList.toggle('open'); });

  // home filters
  var flt = $('flt'), grid = $('grid'), empty = $('empty');
  if (flt && grid) {
    flt.addEventListener('click', function (e) {
      var c = e.target.getAttribute('data-c'); if (!c) return;
      [].forEach.call(flt.children, function (b) { b.classList.toggle('on', b === e.target); });
      var shown = 0;
      [].forEach.call(grid.children, function (card) {
        var ok = c === '*' || card.getAttribute('data-c') === c;
        card.classList.toggle('hide', !ok); if (ok) shown++;
      });
      if (empty) empty.style.display = shown ? 'none' : 'block';
    });
  }

  var prose = $('prose');
  if (prose) {
    // numbered h2 badges
    var n = 0;
    [].forEach.call(prose.querySelectorAll('h2'), function (h) {
      n++; var s = document.createElement('span'); s.className = 'no'; s.textContent = (n < 10 ? '0' : '') + n; h.insertBefore(s, h.firstChild);
    });

    // code block header bars + copy
    [].forEach.call(prose.querySelectorAll('div.highlighter-rouge'), function (blk) {
      var m = (blk.className.match(/language-([\w+#-]+)/) || [])[1] || 'code';
      var bar = document.createElement('div'); bar.className = 'ph';
      var lab = document.createElement('span'); lab.textContent = m === 'plaintext' ? 'text' : m;
      var btn = document.createElement('button'); btn.type = 'button'; btn.textContent = 'copy';
      btn.addEventListener('click', function () {
        var code = blk.querySelector('td.rouge-code pre, td.code pre') || blk.querySelector('pre');
        var txt = code ? code.innerText : '';
        var done = function () { btn.textContent = 'copied'; btn.classList.add('ok'); setTimeout(function () { btn.textContent = 'copy'; btn.classList.remove('ok'); }, 1400); };
        if (navigator.clipboard) navigator.clipboard.writeText(txt).then(done).catch(function () {});
      });
      bar.appendChild(lab); bar.appendChild(btn); blk.insertBefore(bar, blk.firstChild);
    });

    // table of contents
    var list = $('toc-list'), toc = $('toc');
    if (list && toc) {
      var hs = prose.querySelectorAll('h2[id], h3[id]');
      if (hs.length < 2) { toc.style.display = 'none'; $('post-body').classList.add('no-toc'); }
      else {
        var links = [];
        [].forEach.call(hs, function (h) {
          var li = document.createElement('li'), a = document.createElement('a');
          a.href = '#' + h.id; a.className = h.tagName === 'H3' ? 'l3' : 'l2';
          var t = h.cloneNode(true), no = t.querySelector('.no'); if (no) no.remove();
          a.textContent = t.textContent.trim();
          li.appendChild(a); list.appendChild(li); links.push([h, a]);
        });
        var onScroll = function () {
          var cur = null;
          for (var i = 0; i < links.length; i++) { if (links[i][0].getBoundingClientRect().top < 120) cur = links[i][1]; else break; }
          links.forEach(function (x) { x[1].classList.toggle('on', x[1] === cur); });
          if (cur) { var r = cur.getBoundingClientRect(), tr = toc.getBoundingClientRect(); if (r.top < tr.top || r.bottom > tr.bottom) toc.scrollTop += r.top - tr.top - 60; }
        };
        window.addEventListener('scroll', onScroll, { passive: true }); onScroll();
      }
    }
  }

  // back to top
  var top = $('top-btn');
  if (top) {
    window.addEventListener('scroll', function () { top.classList.toggle('show', window.scrollY > 900); }, { passive: true });
    top.addEventListener('click', function () { window.scrollTo({ top: 0, behavior: 'smooth' }); });
  }
})();
