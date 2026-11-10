// Ontwerpreview van de statuspagina tegen de draaiende dienst (zie ontwerpreview.py). Eén toestand per aanroep:
//   node ontwerpreview.mjs <plan.json>
// De browser bezoekt de echte dienst, voert de stappen uit (pagina openen, koppelformulier invullen en versturen) en
// meet daarna op DEZELFDE pagina (geen herladen: een POST-antwoord is niet te herhalen) per thema × breedte:
//   axe-core 4.14 (wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22a, wcag22aa; best-practice apart),
//   contrast in de gerenderde pagina (tekst, betekenisdragende randen, iconen, focusring; opacity en lagen meegerekend),
//   aanraakdoelen (≥ 44 × 44 px; alleen inline links in lopende tekst uitgezonderd), horizontale overloop, tekst ≥ 14 px,
//   ellips, Tab-doorloop (ring ≥ 3 px en ≥ 3:1, in beeld, niet bedekt), Peil-statusregels (icoon + woord bij elke pil,
//   onbekend/verouderd nooit groen, totaal nooit groen als de dienst niet gereed is) en een schermafdruk.
// Uitvoer: <uit>/<toestand>.json en <uit>/afdrukken/<toestand>-<thema>-<breedte>.png. Uitkomst: Sim-getest.
import AxeBuilder from '@axe-core/playwright';
import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const plan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const THEMAS = [
  { naam: 'licht', schema: 'light' },
  { naam: 'donker', schema: 'dark' },
];
const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22a', 'wcag22aa'];
const TRACE = '5e1f0c2a-8b3d-4c7e-9a10-' + (plan.toestand.length.toString(16).padStart(2, '0') + 'b2c4d6e8f0a1').slice(0, 12);

// ------------------------------------------------------------------------------------------- metingen in de pagina
const METING = () => {
  const cvs = document.createElement('canvas');
  cvs.width = cvs.height = 1;
  const ctx = cvs.getContext('2d', { willReadFrequently: true });
  const cache = new Map();
  const rgba = (s) => {
    if (cache.has(s)) return cache.get(s);
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillStyle = '#000';
    ctx.fillStyle = s;
    ctx.fillRect(0, 0, 1, 1);
    const d = ctx.getImageData(0, 0, 1, 1).data;
    const v = [d[0], d[1], d[2], d[3] / 255];
    cache.set(s, v);
    return v;
  };
  const over = (t, b) => {
    const a = t[3] + b[3] * (1 - t[3]);
    if (a === 0) return [0, 0, 0, 0];
    return [0, 1, 2].map((i) => (t[i] * t[3] + b[i] * b[3] * (1 - t[3])) / a).concat([a]);
  };
  const lum = (c) => {
    const f = (v) => ((v /= 255) <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4));
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
  };
  const ratio = (a, b) => {
    const x = lum(a);
    const y = lum(b);
    return +((Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05)).toFixed(2);
  };
  const hex = (c) => '#' + c.slice(0, 3).map((v) => Math.round(v).toString(16).padStart(2, '0')).join('');
  const keten = (el) => {
    const c = [];
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) c.push(e);
    return c.reverse();
  };
  // geschilderde achtergrond onder (en met) el: alle lagen van boven naar beneden op wit, met opacity
  const vlak = (el) => {
    let c = [255, 255, 255, 1];
    for (const e of keten(el)) {
      const cs = getComputedStyle(e);
      const o = parseFloat(cs.opacity);
      const laag = rgba(cs.backgroundColor);
      c = over([laag[0], laag[1], laag[2], laag[3] * o], c);
    }
    return c;
  };
  const isSr = (el) =>
    keten(el).some((e) => {
      const cs = getComputedStyle(e);
      return cs.position === 'absolute' && parseFloat(cs.width) <= 1 && parseFloat(cs.height) <= 1 && cs.overflow === 'hidden';
    });
  const zichtbaar = (el) => {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return false;
    const cs = getComputedStyle(el);
    if (cs.visibility === 'hidden' || cs.display === 'none') return false;
    if (r.bottom < 0 && el.classList.contains('spring')) return false; // skiplink buiten beeld tot focus
    return !isSr(el);
  };
  const desc = (el) => {
    const cls = (el.getAttribute('class') || '').split(/\s+/).filter(Boolean).slice(0, 2).join('.');
    return el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + (cls ? '.' + cls : '');
  };
  const eigenTekst = (el) =>
    [...el.childNodes]
      .filter((n) => n.nodeType === 3)
      .map((n) => n.textContent)
      .join('')
      .replace(/\s+/g, ' ')
      .trim();

  // tekst
  const tekst = [];
  for (const el of document.querySelectorAll('body *')) {
    if (['SCRIPT', 'STYLE', 'svg', 'use', 'symbol'].includes(el.tagName)) continue;
    const t = eigenTekst(el);
    if (!t || !zichtbaar(el)) continue;
    const cs = getComputedStyle(el);
    const bg = vlak(el);
    const fg = over(rgba(cs.color), bg);
    const fs = parseFloat(cs.fontSize);
    const fw = parseInt(cs.fontWeight, 10);
    const groot = fs >= 24 || (fs >= 18.66 && fw >= 700);
    tekst.push({ el: desc(el), t: t.slice(0, 50), fs, fw, groot, r: ratio(fg, bg), fg: hex(fg), bg: hex(bg), ellips: cs.textOverflow === 'ellipsis' && el.scrollWidth > el.clientWidth + 1 });
  }

  // betekenisdragende randen (WCAG 1.4.11) en decoratieve randen (alleen gemeld)
  const BETEKENIS = '.pil, .veld input, .knop, .selecteer, .melding, .voorbeeld';
  const randen = [];
  for (const el of document.querySelectorAll('body *')) {
    if (!zichtbaar(el)) continue;
    const cs = getComputedStyle(el);
    const w = parseFloat(cs.borderTopWidth);
    const kleur = rgba(cs.borderTopColor);
    if (!(w > 0) || cs.borderTopStyle === 'none' || kleur[3] === 0) continue;
    const buiten = vlak(el.parentElement);
    const binnen = vlak(el);
    const rk = over(kleur, buiten);
    randen.push({
      el: desc(el),
      t: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 30),
      betekenis: el.matches(BETEKENIS),
      stijl: cs.borderTopStyle,
      w,
      buiten: ratio(rk, buiten),
      binnen: ratio(rk, binnen),
      kleur: hex(rk),
    });
  }

  // iconen (grafische objecten met betekenis: statuspillen, meldingen, veldfouten) tegen hun vlak
  const iconen = [];
  for (const svg of document.querySelectorAll('body svg:not([style*="display:none"])')) {
    if (!zichtbaar(svg)) continue;
    const use = svg.querySelector('use');
    const cs = getComputedStyle(svg);
    const bg = vlak(svg.parentElement);
    const fg = over(rgba(cs.stroke === 'none' ? cs.color : cs.color), bg);
    iconen.push({ el: desc(svg.parentElement), icoon: use ? use.getAttribute('href') : '', r: ratio(fg, bg), kleur: hex(fg) });
  }

  // aanraakdoelen
  const doelen = [];
  for (const el of document.querySelectorAll('a[href], button, input:not([type=hidden]), select, textarea, summary')) {
    if (!zichtbaar(el)) continue;
    const r = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    const inline = el.tagName === 'A' && cs.display === 'inline' && el.parentElement && eigenTekst(el.parentElement).length > 0;
    doelen.push({ el: desc(el), t: (el.innerText || el.getAttribute('aria-label') || '').trim().slice(0, 40), w: Math.round(r.width), h: Math.round(r.height), inline });
  }

  // Peil-statusregels
  const pillen = [...document.querySelectorAll('.pil')].map((p) => ({
    klasse: [...p.classList].find((c) => c.startsWith('pil-')) || '',
    icoon: p.querySelector('svg use')?.getAttribute('href') || '',
    woord: (p.textContent || '').replace(/\s+/g, ' ').trim(),
    // Peil 1.1.1: de naam eindigt op een verborgen ':' (schermlezerscheiding) en de reden staat in .sub > span
    rij: (p.closest('li')?.querySelector('.naam')?.textContent || p.closest('section')?.querySelector('h2')?.textContent || '')
      .trim()
      .replace(/:$/, ''),
    reden: (p.closest('li')?.querySelector('.sub > span')?.textContent || '').trim(),
  }));
  const gereedDt = [...document.querySelectorAll('.feiten dt')].find((dt) => dt.textContent === 'Gereed');
  const se = document.scrollingElement;
  const kopjes = [...document.querySelectorAll('h1,h2,h3,h4')].map((h) => +h.tagName[1]);
  const sprongen = kopjes.filter((n, i) => i > 0 && n > kopjes[i - 1] + 1).length;
  const ids = [...document.querySelectorAll('[id]')].map((e) => e.id);
  const kapot = [...document.querySelectorAll('[aria-describedby],[aria-labelledby]')].flatMap((e) =>
    `${e.getAttribute('aria-describedby') || ''} ${e.getAttribute('aria-labelledby') || ''}`.split(/\s+/).filter((id) => id && !document.getElementById(id)),
  );
  return {
    tekst,
    randen,
    iconen,
    doelen,
    pillen,
    gereed: gereedDt?.nextElementSibling?.textContent || '',
    totaal: pillen[0] || null,
    overloop: se.scrollWidth - se.clientWidth,
    hoogte: se.scrollHeight,
    h1: document.querySelectorAll('h1').length,
    sprongen,
    dubbeleIds: ids.filter((id, i) => ids.indexOf(id) !== i),
    kapotteVerwijzingen: kapot,
    titel: document.title,
    rollen: [...document.querySelectorAll('[role]')].map((e) => `${desc(e)}[role=${e.getAttribute('role')}]`),
  };
};

const FOCUS = () => {
  const el = document.activeElement;
  if (!el || el === document.body) return null;
  const cvs = document.createElement('canvas');
  cvs.width = cvs.height = 1;
  const ctx = cvs.getContext('2d');
  const rgba = (s) => {
    ctx.clearRect(0, 0, 1, 1);
    ctx.fillStyle = '#000';
    ctx.fillStyle = s;
    ctx.fillRect(0, 0, 1, 1);
    const d = ctx.getImageData(0, 0, 1, 1).data;
    return [d[0], d[1], d[2], d[3] / 255];
  };
  const over = (t, b) => {
    const a = t[3] + b[3] * (1 - t[3]);
    return [0, 1, 2].map((i) => (t[i] * t[3] + b[i] * b[3] * (1 - t[3])) / (a || 1)).concat([a]);
  };
  const lum = (c) => {
    const f = (v) => ((v /= 255) <= 0.04045 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4));
    return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
  };
  const ratio = (a, b) => +((Math.max(lum(a), lum(b)) + 0.05) / (Math.min(lum(a), lum(b)) + 0.05)).toFixed(2);
  const vlak = (e) => {
    const lagen = [];
    for (let p = e; p && p.nodeType === 1; p = p.parentElement) lagen.push(rgba(getComputedStyle(p).backgroundColor));
    let c = [255, 255, 255, 1];
    for (const l of lagen.reverse()) c = over(l, c);
    return c;
  };
  // vaste volgnummers: twee links met dezelfde tekst (skiplink en meldingslink) zijn verschillende tabstops
  if (!el.dataset.reviewTab) el.dataset.reviewTab = String(document.querySelectorAll('[data-review-tab]').length + 1);
  const cs = getComputedStyle(el);
  const r = el.getBoundingClientRect();
  // per regelvak (een inline link kan over twee regels lopen; zijn omhullende rechthoek bevat dan andere tekst)
  const punten = [...el.getClientRects()].flatMap((v) => [
    [v.left + v.width / 2, v.top + v.height / 2],
    [v.left + 2, v.top + 2],
    [v.right - 2, v.bottom - 2],
  ]);
  let inBeeld = 0;
  let onbedekt = 0;
  for (const [x, y] of punten) {
    if (x < 0 || y < 0 || x > innerWidth || y > innerHeight) continue;
    inBeeld++;
    const top = document.elementFromPoint(x, y);
    if (top && (top === el || el.contains(top))) onbedekt++;
  }
  const ring = rgba(cs.outlineColor);
  const buiten = vlak(el.parentElement);
  const halo = cs.boxShadow !== 'none' ? (cs.boxShadow.match(/rgba?\([^)]*\)/) || [null])[0] : null;
  return {
    nr: el.dataset.reviewTab,
    el: el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') + ' "' + (el.innerText || el.getAttribute('href') || '').trim().slice(0, 40) + '"',
    breedte: parseFloat(cs.outlineWidth),
    stijl: cs.outlineStyle,
    ringBuiten: ratio(over(ring, buiten), buiten),
    ringHalo: halo ? ratio(over(ring, buiten), over(rgba(halo), buiten)) : null,
    inBeeld,
    onbedekt,
    top: Math.round(r.top),
    bottom: Math.round(r.bottom),
  };
};

// ------------------------------------------------------------------------------------------- uitvoering
const browser = await chromium.launch();
const context = await browser.newContext({ locale: 'nl-NL', timezoneId: 'UTC', reducedMotion: 'reduce' });
const page = await context.newPage();
await page.setExtraHTTPHeaders({ 'X-Trace-Id': TRACE });
const csp = [];
const paginafouten = [];
page.on('console', (m) => {
  if (/Content Security Policy|Refused to/i.test(m.text())) csp.push(m.text());
});
page.on('pageerror', (e) => paginafouten.push(String(e)));
await page.setViewportSize({ width: 390, height: 900 });

let antwoord = null;
for (const stap of plan.stappen) {
  if (stap.soort === 'goto') {
    antwoord = await page.goto(plan.url + stap.pad);
  } else if (stap.soort === 'formulier') {
    for (let i = 0; i < (stap.keer || 1); i++) {
      await page.fill('#hub', stap.hub);
      await page.fill('#koppelcode', stap.koppelcode);
      await page.fill('#vingerafdruk', stap.vingerafdruk);
      [antwoord] = await Promise.all([page.waitForNavigation(), page.click('form[action="/koppelen"] button[type=submit]')]);
    }
  }
}
const html = await page.content();
for (const v of plan.verwacht) {
  if (!html.includes(v)) {
    console.error(`${plan.toestand}: verwacht '${v}' niet op de pagina (HTTP ${antwoord?.status()})`);
    process.exit(2);
  }
}
const headers = antwoord ? await antwoord.allHeaders() : {};
const resultaat = {
  toestand: plan.toestand,
  beschrijving: plan.beschrijving,
  status: antwoord?.status() ?? null,
  csp: headers['content-security-policy'] || null,
  traceHeader: headers['x-trace-id'] || null,
  aria: await page.locator('body').ariaSnapshot(),
  runs: [],
};

for (const thema of THEMAS) {
  await page.emulateMedia({ colorScheme: thema.schema, reducedMotion: 'reduce' });
  for (const breedte of plan.breedtes) {
    await page.setViewportSize({ width: breedte, height: 900 });
    await page.evaluate(() => window.scrollTo(0, 0));
    const m = await page.evaluate(METING);
    const axe = await new AxeBuilder({ page }).withTags(WCAG).analyze();
    const bp = await new AxeBuilder({ page }).withTags(['best-practice']).analyze();

    // Tab-doorloop vanaf het begin van het document (focus op body zet het startpunt; geen herladen nodig)
    await page.evaluate(() => {
      document.body.setAttribute('tabindex', '-1');
      document.body.focus();
      document.body.removeAttribute('tabindex');
      window.scrollTo(0, 0);
    });
    const focus = [];
    for (let i = 0; i < 40; i++) {
      await page.keyboard.press('Tab');
      const f = await page.evaluate(FOCUS);
      if (!f || focus.some((g) => g.nr === f.nr)) break; // rond: terug bij een eerder element
      focus.push(f);
    }
    await page.evaluate(() => document.activeElement?.blur());
    await page.evaluate(() => window.scrollTo(0, 0));
    const afdruk = path.join(plan.uit, 'afdrukken', `${plan.toestand}-${thema.naam}-${breedte}.png`);
    await page.screenshot({ path: afdruk, fullPage: true });

    const tekstFout = m.tekst.filter((t) => t.r < (t.groot ? 3 : 4.5));
    const tekstOnderPeil = m.tekst.filter((t) => t.r < 7);
    resultaat.runs.push({
      thema: thema.naam,
      breedte,
      axe: axe.violations.map((v) => ({ id: v.id, impact: v.impact, doelen: v.nodes.map((n) => n.target.join(' ')).slice(0, 5) })),
      bestPractice: bp.violations.map((v) => ({ id: v.id, doelen: v.nodes.map((n) => n.target.join(' ')).slice(0, 5) })),
      tekst: { aantal: m.tekst.length, min: Math.min(...m.tekst.map((t) => t.r)), fouten: tekstFout, onderPeil7: tekstOnderPeil, klein: m.tekst.filter((t) => t.fs < 14), ellips: m.tekst.filter((t) => t.ellips) },
      randen: { betekenisMin: Math.min(99, ...m.randen.filter((r) => r.betekenis).map((r) => r.buiten)), fouten: m.randen.filter((r) => r.betekenis && r.buiten < 3), decoratief: m.randen.filter((r) => !r.betekenis).reduce((a, r) => Math.min(a, r.buiten), 99) },
      iconen: { min: Math.min(99, ...m.iconen.map((i) => i.r)), fouten: m.iconen.filter((i) => i.r < 3) },
      doelen: { fouten: m.doelen.filter((d) => !d.inline && (d.w < 44 || d.h < 44)), inline: m.doelen.filter((d) => d.inline) },
      focus: {
        aantal: focus.length,
        eerste: focus[0]?.el ?? null,
        min: Math.min(99, ...focus.map((f) => Math.min(f.ringBuiten, f.ringHalo ?? 99))),
        fouten: focus.filter((f) => f.stijl === 'none' || f.breedte < 3 || f.ringBuiten < 3 || (f.ringHalo !== null && f.ringHalo < 3) || f.inBeeld === 0 || f.onbedekt === 0),
      },
      overloop: m.overloop,
      hoogte: m.hoogte,
      structuur: { h1: m.h1, sprongen: m.sprongen, dubbeleIds: m.dubbeleIds, kapotteVerwijzingen: m.kapotteVerwijzingen, titel: m.titel, rollen: m.rollen },
      pillen: m.pillen,
      gereed: m.gereed,
      afdruk: path.relative(plan.uit, afdruk),
    });
  }
}
// WCAG 1.4.12 tekstafstand: regelhoogte 1,5, alinea's 2×, letters 0,12 em, woorden 0,16 em op 320 px — geen overloop
// en geen afgekapte tekst (een inline <style> mag volgens de CSP: style-src 'unsafe-inline')
await page.setViewportSize({ width: 320, height: 900 });
await page.addStyleTag({
  content: '*{line-height:1.5!important;letter-spacing:.12em!important;word-spacing:.16em!important}p{margin-bottom:2em!important}',
});
resultaat.tekstafstand = await page.evaluate(() => {
  const se = document.scrollingElement;
  const afgekapt = [...document.querySelectorAll('body *')].filter((el) => {
    const cs = getComputedStyle(el);
    return /hidden|clip/.test(cs.overflow) && el.getBoundingClientRect().width > 1 && (el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1);
  });
  return { overloop: se.scrollWidth - se.clientWidth, afgekapt: afgekapt.map((el) => el.tagName.toLowerCase() + '.' + el.className) };
});
resultaat.csp_overtredingen = csp;
resultaat.paginafouten = paginafouten;
fs.writeFileSync(path.join(plan.uit, `${plan.toestand}.json`), JSON.stringify(resultaat, null, 1));
await browser.close();
console.log(`${plan.toestand}: HTTP ${resultaat.status}, ${resultaat.runs.length} metingen`);
