// Statuspagina van home-control-hub in Peil (HC11; ONTWERPTAAL §12 testmatrix en §13.2; contract 1.2 §3.7).
// Per toestand × thema (licht/donker) × breedte (320/360/390/768/1024/1440):
//   axe-core (wcag2a, wcag2aa, wcag21a, wcag21aa, wcag22aa + best-practice) = 0 overtredingen,
//   geen horizontale overloop, geen JavaScript, geen CSP-overtreding of extern verzoek,
//   aanraakdoelen ≥ 44 px, tekst ≥ 14 px, één h1, geen dubbele id's of kapotte aria-verwijzingen,
//   eerste signaal nooit groen als de dienst niet gereed is, fout = code + selecteerbare trace-ID,
//   Tab-doorloop met zichtbare ring ≥ 3 px (390 en 1440) en stippelranden bij forced colors.
// De pagina's komen uit de echte app tegen de Hub-simulator (genereer_toestanden.py) — uitkomst: Sim-getest.
// SCHERMAFDRUKKEN=1: verplichte toestanden × 360/768/1440 × licht/donker naar docs/screenshots/peil/statuspagina/.
import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const UIT = process.env.STATUSPAGINA_UIT ?? path.join(__dirname, 'uit');
const AFDRUKKEN = path.resolve(__dirname, '../../docs/screenshots/peil/statuspagina');
const BREEDTES = [320, 360, 390, 768, 1024, 1440];
const AFDRUK_BREEDTES = [360, 768, 1440];
const VERPLICHT = ['niet-gekoppeld', 'koppelen-mislukt', 'gekoppeld', 'ingetrokken', 'niet-gereed'];
const THEMAS = [
  { naam: 'licht', schema: 'light' as const, achtergrond: 'rgb(238, 241, 245)' },
  { naam: 'donker', schema: 'dark' as const, achtergrond: 'rgb(10, 13, 18)' },
];
const ADRES = 'http://home-control-hub.test:30420/';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

type Meta = { toestand: string; beschrijving: string; status: number; headers: Record<string, string> };

function toestanden(): { naam: string; body: string; meta: Meta }[] {
  if (!fs.existsSync(UIT)) throw new Error(`Geen toestanden in ${UIT}: draai eerst python tests/ui/genereer_toestanden.py`);
  const namen = fs
    .readdirSync(UIT)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.slice(0, -5))
    .sort();
  for (const v of VERPLICHT) if (!namen.includes(v)) throw new Error(`verplichte toestand ${v} ontbreekt in ${UIT}`);
  return namen.map((naam) => ({
    naam,
    body: fs.readFileSync(path.join(UIT, `${naam}.html`), 'utf8'),
    meta: JSON.parse(fs.readFileSync(path.join(UIT, `${naam}.json`), 'utf8')) as Meta,
  }));
}

async function serveer(page: Page, body: string, meta: Meta, extern: string[]): Promise<void> {
  await page.route('**/*', async (route) => {
    if (route.request().url() !== ADRES) {
      extern.push(route.request().url()); // de pagina mag niets anders laden (CSP default-src 'none')
      await route.abort();
      return;
    }
    const headers = { ...meta.headers };
    delete headers['content-length'];
    await route.fulfill({ status: meta.status, headers, body });
  });
}

for (const { naam, body, meta } of toestanden()) {
  for (const thema of THEMAS) {
    test(`${naam} · ${thema.naam}`, async ({ page }) => {
      const csp: string[] = [];
      const fouten: string[] = [];
      const extern: string[] = [];
      page.on('console', (m) => {
        if (/Content Security Policy|Refused to/i.test(m.text())) csp.push(m.text());
      });
      page.on('pageerror', (e) => fouten.push(String(e)));
      await page.emulateMedia({ colorScheme: thema.schema, reducedMotion: 'reduce' });
      await serveer(page, body, meta, extern);
      expect(meta.headers['content-security-policy']).toContain("default-src 'none'");
      expect(meta.headers['content-security-policy']).not.toContain('script-src');
      expect(body.startsWith('<!doctype html>')).toBe(true);
      expect(body).not.toMatch(/<script|javascript:|\son[a-z]+\s*=/i); // geen JS, ook geen event-attributen

      for (const breedte of BREEDTES) {
        await page.setViewportSize({ width: breedte, height: 900 });
        await page.goto(ADRES);
        const plek = `${naam} · ${thema.naam} · ${breedte}px`;

        const achtergrond = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
        expect(achtergrond, `${plek}: thema actief`).toBe(thema.achtergrond);

        const axe = await new AxeBuilder({ page })
          .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa', 'best-practice'])
          .analyze();
        const overtredingen = axe.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
        expect(overtredingen, `${plek}: axe`).toEqual([]);

        const m = await page.evaluate(() => {
          const zichtbaar = (el: Element) => {
            const r = el.getBoundingClientRect();
            const s = getComputedStyle(el);
            return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
          };
          const doc = document.documentElement;
          const doelen = [...document.querySelectorAll('button, input:not([type=hidden]), .voet a, .knop')].filter(zichtbaar);
          const tekst = [...document.querySelectorAll('body *')]
            .filter((el) => [...el.childNodes].some((n) => n.nodeType === 3 && (n.textContent ?? '').trim() !== ''))
            .filter(zichtbaar);
          const ids = [...document.querySelectorAll('[id]')].map((el) => el.id);
          const verwijzingen = [...document.querySelectorAll('[aria-describedby], [aria-labelledby]')].flatMap((el) =>
            `${el.getAttribute('aria-describedby') ?? ''} ${el.getAttribute('aria-labelledby') ?? ''}`
              .split(/\s+/)
              .filter(Boolean),
          );
          const totaal = document.querySelector('.totaal .pil');
          const gereed = [...document.querySelectorAll('.feiten dt')].find((dt) => dt.textContent === 'Gereed');
          const trace = document.querySelector('.melding .selecteer');
          return {
            overloop: Math.max(doc.scrollWidth, document.body.scrollWidth) - window.innerWidth,
            kleineDoelen: doelen
              .filter((el) => el.getBoundingClientRect().height < 44)
              .map((el) => `${el.tagName.toLowerCase()}#${el.id || (el.textContent ?? '').trim().slice(0, 30)}`),
            kleineTekst: tekst
              .filter((el) => parseFloat(getComputedStyle(el).fontSize) < 14)
              .map((el) => `${el.tagName.toLowerCase()}: ${(el.textContent ?? '').trim().slice(0, 30)}`),
            h1: document.querySelectorAll('h1').length,
            scripts: document.querySelectorAll('script, [onclick], [onload]').length,
            dubbeleIds: ids.filter((id, i) => ids.indexOf(id) !== i),
            kapotteVerwijzingen: verwijzingen.filter((id) => !document.getElementById(id)),
            totaalKlasse: totaal?.className ?? '',
            gereed: gereed?.nextElementSibling?.textContent ?? '',
            titel: document.title,
            trace: trace?.textContent ?? null,
            traceSelecteerbaar: trace ? getComputedStyle(trace).userSelect : null,
            code: document.querySelector('.melding code:not(.selecteer)')?.textContent ?? null,
            formulier: document.querySelectorAll('form[action="/koppelen"]').length,
            ontkoppelen: document.querySelectorAll('form[action="/ontkoppelen"], form[action="/beheer"]').length,
          };
        });
        expect(m.overloop, `${plek}: horizontale overloop`).toBeLessThanOrEqual(0);
        expect(m.kleineDoelen, `${plek}: doelen < 44 px`).toEqual([]);
        expect(m.kleineTekst, `${plek}: tekst < 14 px`).toEqual([]);
        expect(m.h1, plek).toBe(1);
        expect(m.scripts, plek).toBe(0);
        expect(m.dubbeleIds, plek).toEqual([]);
        expect(m.kapotteVerwijzingen, plek).toEqual([]);
        expect(m.ontkoppelen, `${plek}: geen ontkoppelen op de statuspagina`).toBe(0);
        // eerste signaal: nooit groen als de dienst niet gereed is
        if (m.gereed.startsWith('Nee')) {
          expect(m.totaalKlasse, plek).not.toContain('pil-gezond');
          expect(m.titel, plek).not.toMatch(/gezond/);
        } else {
          expect(m.gereed, plek).toBe('Ja');
        }
        // een fout heeft altijd een vaste code en een selecteerbare trace-ID; een mislukte poging is nooit 200
        if (m.trace !== null) {
          expect(m.trace, plek).toMatch(UUID);
          expect(m.traceSelecteerbaar, plek).toBe('all');
          expect(m.code, plek).toMatch(/^[a-z_]+$/);
          expect(meta.headers['x-trace-id'], plek).toBe(m.trace);
        }
        if (m.titel.includes('koppelen mislukt')) {
          expect(meta.status, plek).toBeGreaterThanOrEqual(400);
          expect(m.trace, plek).not.toBeNull();
        }

        // toetsenbord: eerste Tab = skiplink; elk focusbaar element krijgt een ring ≥ 3 px en is in beeld
        if (breedte === 390 || breedte === 1440) {
          const aantal = await page.locator('a[href], button, input:not([type=hidden])').count();
          for (let i = 0; i < aantal; i++) {
            await page.keyboard.press('Tab');
            const ring = await page.evaluate(() => {
              const el = document.activeElement as HTMLElement | null;
              if (!el || el === document.body) return null;
              const s = getComputedStyle(el);
              const r = el.getBoundingClientRect();
              return {
                naam: `${el.tagName.toLowerCase()} ${el.getAttribute('href') ?? el.id}`,
                breedte: parseFloat(s.outlineWidth),
                stijl: s.outlineStyle,
                inBeeld: r.bottom > 0 && r.top < window.innerHeight && r.left >= 0 && r.right <= window.innerWidth,
              };
            });
            expect(ring, `${plek}: Tab ${i + 1}`).not.toBeNull();
            if (i === 0) expect(ring!.naam, plek).toMatch(/^a #/);
            expect(ring!.stijl, `${plek}: ${ring!.naam}`).not.toBe('none');
            expect(ring!.breedte, `${plek}: ${ring!.naam}`).toBeGreaterThanOrEqual(3);
            expect(ring!.inBeeld, `${plek}: ${ring!.naam} niet in beeld bij focus`).toBe(true);
          }
        }

        if (process.env.SCHERMAFDRUKKEN && VERPLICHT.includes(naam) && AFDRUK_BREEDTES.includes(breedte)) {
          fs.mkdirSync(AFDRUKKEN, { recursive: true });
          await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
          await page.screenshot({ path: path.join(AFDRUKKEN, `${naam}-${thema.naam}-${breedte}.png`), fullPage: true });
        }
      }

      // forced colors (A-18): stippelranden blijven zichtbaar voor 'onbekend'
      await page.emulateMedia({ colorScheme: thema.schema, forcedColors: 'active' });
      await page.setViewportSize({ width: 360, height: 900 });
      await page.goto(ADRES);
      const stippel = await page.evaluate(() =>
        [...document.querySelectorAll('.pil-onbekend')].map((el) => getComputedStyle(el).borderTopStyle),
      );
      for (const s of stippel) expect(s, `${naam}: forced colors`).toBe('dashed');

      expect(csp, 'CSP-overtredingen').toEqual([]);
      expect(fouten, 'paginafouten').toEqual([]);
      expect(extern, 'externe verzoeken').toEqual([]);
    });
  }
}
