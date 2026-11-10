// Browsertest van het koppelformulier tegen de ECHTE dienst (contract 1.3 §3.7 punt 6; C1.3-HCH-01):
//   HERKOMST_FASE=negatief|positief node herkomst.mjs <plan.json>     plan: {url, poort, hub, code, vinger, uit}
// Chromium opent de echte statuspagina en verstuurt een echt formulier; de headers maakt de browser zelf (Playwright kan
// Origin en Sec-Fetch-Site van een navigatie niet overschrijven, dus elk geval ontstaat zoals in het echt):
//   origin-null     de pagina komt (zoals in 1.2) met Referrer-Policy: no-referrer → de browser stuurt Origin: null
//   cross-site      een formulier op een andere website (http://kwaadaardig.example) → vreemde Origin, cross-site
//   same-site       een andere app op hetzelfde NAS-adres (andere poort), mét het echte formuliertoken → same-site
//   geen-cookie     cookies gewist vóór het versturen
//   host-domeinnaam de pagina via een publieke domeinnaam die naar 127.0.0.1 wijst (DNS-rebinding: Origin = Host)
// Elk geval moet 403 geven met de vaste code; ontwerpreview.py controleert daarna dat de Hub-simulator niets kreeg en de
// koppelstatus ongewijzigd is. Fase "positief": het echte formulier koppelt wél (303 → "Gekoppeld met de Hub").
// Uitvoer: <uit>/herkomst-<fase>.json (met de headers zoals de browser ze verstuurde). Uitkomst: Sim-getest.
import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const plan = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const fase = process.env.HERKOMST_FASE ?? 'negatief';
const DOMEIN = 'nas.voorbeeld.nl'; // publieke domeinnaam; de browser lost hem op naar 127.0.0.1 (rebinding)
const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP ${DOMEIN} 127.0.0.1`] });
const resultaten = [];
const fouten = [];
const HEADERS = ['origin', 'sec-fetch-site', 'host', 'referer'];

function aanvalspagina(doel, csrf) {
  const velden = { csrf, hub_adres: plan.hub, koppelcode: plan.code, hub_vingerafdruk: plan.vinger };
  const inputs = Object.entries(velden)
    .map(([k, v]) => `<input type="hidden" name="${k}" value="${String(v).replace(/"/g, '&quot;')}">`)
    .join('');
  return `<!doctype html><html lang="nl"><title>Andere site</title><form method="post" action="${doel}/koppelen">${inputs}<button type="submit">Verstuur</button></form></html>`;
}

async function poging(naam, { verwacht, code, zonderCookie, url = plan.url, aanvaller, noReferrer }) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const verzonden = [];
  page.on('request', async (req) => {
    if (req.method() !== 'POST' || !req.url().endsWith('/koppelen')) return;
    const h = await req.allHeaders();
    verzonden.push({ ...Object.fromEntries(HEADERS.map((k) => [k, h[k] ?? null])), cookie: Boolean(h.cookie) });
  });
  try {
    if (noReferrer) {
      // de pagina zoals 1.2 hem stuurde: met no-referrer stuurt elke browser bij een formulier-POST Origin: null
      await page.route(`${url}/`, async (route) => {
        const antwoord = await route.fetch();
        await route.fulfill({ response: antwoord, headers: { ...antwoord.headers(), 'referrer-policy': 'no-referrer' } });
      });
    }
    await page.goto(`${url}/`);
    const melding = await page
      .locator('.melding code:not(.selecteer)')
      .first()
      .textContent({ timeout: 2000 })
      .catch(() => null);
    let klik;
    if (aanvaller) {
      const csrf = await page.inputValue('input[name="csrf"]', { timeout: 5000 });
      await page.route(`${aanvaller}/aanval.html`, (route) =>
        route.fulfill({ contentType: 'text/html', body: aanvalspagina(url, csrf) }),
      );
      await page.goto(`${aanvaller}/aanval.html`);
      klik = () => page.click('button[type=submit]');
    } else {
      if (zonderCookie) await ctx.clearCookies();
      await page.fill('#hub', plan.hub, { timeout: 5000 });
      await page.fill('#koppelcode', plan.code);
      await page.fill('#vingerafdruk', plan.vinger);
      klik = () => page.click('form[action="/koppelen"] button[type=submit]');
    }
    const [antwoord] = await Promise.all([
      page.waitForResponse((r) => r.request().method() === 'POST' && r.url().endsWith('/koppelen')),
      klik(),
    ]);
    await page.waitForLoadState('load');
    const status = antwoord.status();
    const gevonden = await page
      .locator('.melding code:not(.selecteer)')
      .first()
      .textContent({ timeout: 2000 })
      .catch(() => null);
    const tekst = await page.locator('main').innerText();
    const r = { naam, status, code: gevonden, melding_bij_laden: melding, verzonden };
    resultaten.push(r);
    if (status !== verwacht) fouten.push(`${naam}: HTTP ${status}, verwacht ${verwacht}`);
    if (code && gevonden !== code) fouten.push(`${naam}: code ${gevonden}, verwacht ${code}`);
    if (verwacht === 303 && !tekst.includes('Gekoppeld met de Hub')) fouten.push(`${naam}: geen melding 'Gekoppeld'`);
    if (verwacht === 403 && !tekst.includes('Er is niets naar de Hub gestuurd.')) fouten.push(`${naam}: tekst ontbreekt`);
    return r;
  } catch (e) {
    const fout = String(e).split('\n')[0];
    fouten.push(`${naam}: ${fout}`);
    const r = { naam, status: null, code: null, melding_bij_laden: null, verzonden, fout };
    resultaten.push(r);
    return r;
  } finally {
    await ctx.close();
  }
}

const eerste = (r, k) => r.verzonden[0]?.[k] ?? null;
if (fase === 'negatief') {
  const nul = await poging('origin-null', { verwacht: 403, code: 'herkomst_onjuist', noReferrer: true });
  if (eerste(nul, 'origin') !== 'null') fouten.push(`origin-null: de browser stuurde Origin ${eerste(nul, 'origin')}`);
  const vreemd = await poging('cross-site', {
    verwacht: 403,
    code: 'herkomst_onjuist',
    aanvaller: 'http://kwaadaardig.example',
  });
  if (eerste(vreemd, 'origin') !== 'http://kwaadaardig.example') fouten.push('cross-site: Origin is niet de vreemde site');
  // Chromium stuurt Sec-Fetch-* alleen naar 'potentially trustworthy' adressen en niet altijd vanaf een http-pagina;
  // stuurt hij hem, dan moet hij kloppen. De controle op de header zelf staat ook in de HTTP-tests
  // (apps/api/tests/integration/test_contract_1_3_statuspagina.py).
  if (![null, 'cross-site'].includes(eerste(vreemd, 'sec-fetch-site'))) fouten.push('cross-site: Sec-Fetch-Site klopt niet');
  const zelfdeSite = await poging('same-site', {
    verwacht: 403,
    code: 'herkomst_onjuist',
    aanvaller: `http://127.0.0.1:${plan.poort + 1}`,
  });
  if (![null, 'same-site'].includes(eerste(zelfdeSite, 'sec-fetch-site'))) fouten.push('same-site: Sec-Fetch-Site klopt niet');
  if (eerste(zelfdeSite, 'origin') !== `http://127.0.0.1:${plan.poort + 1}`) fouten.push('same-site: Origin is niet de buurapp');
  if (!zelfdeSite.verzonden[0]?.cookie) fouten.push('same-site: het cookie (SameSite=Strict) ging niet mee');
  const zonder = await poging('geen-cookie', { verwacht: 403, code: 'ongeldig_formulier', zonderCookie: true });
  if (zonder.verzonden[0]?.cookie !== false) fouten.push('geen-cookie: er ging toch een cookie mee');
  const host = await poging('host-domeinnaam', {
    verwacht: 403,
    code: 'host_niet_toegestaan',
    url: `http://${DOMEIN}:${plan.poort}`,
  });
  if (host.melding_bij_laden !== 'host_niet_toegestaan') fouten.push('host-domeinnaam: geen melding bij het laden');
  if (eerste(host, 'origin') !== `http://${DOMEIN}:${plan.poort}`) fouten.push('host-domeinnaam: Origin ≠ Host');
} else {
  // het echte formulier koppelt wél; de browser stuurt zelf Origin = schema://Host en Sec-Fetch-Site same-origin
  const echt = await poging('echt-formulier', { verwacht: 303 });
  if (eerste(echt, 'origin') !== plan.url) fouten.push(`echt-formulier: Origin ${eerste(echt, 'origin')}`);
  if (eerste(echt, 'sec-fetch-site') !== 'same-origin') fouten.push('echt-formulier: Sec-Fetch-Site');
  if (!echt.verzonden[0]?.cookie) fouten.push('echt-formulier: geen cookie meegestuurd');
}
await browser.close();
fs.mkdirSync(plan.uit, { recursive: true });
fs.writeFileSync(path.join(plan.uit, `herkomst-${fase}.json`), JSON.stringify({ resultaten, fouten }, null, 1));
for (const f of fouten) console.error(`  - ${f}`);
console.log(`herkomst (${fase}): ${resultaten.length} gevallen, ${fouten.length} fouten`);
process.exit(fouten.length ? 1 : 0);
