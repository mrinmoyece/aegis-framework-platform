# Layer 12 accessibility target and checklist

The target is WCAG 2.2 AA. Automated axe and Playwright checks are regression evidence,
not an independent accessibility audit or assistive-technology qualification.

## Implemented baseline

- skip link, one main landmark, labeled navigation, page headings, sections and footer;
- native links/buttons/select/input/textarea/checkbox controls with visible focus;
- table captions, column headers, bounded horizontal regions, and empty states;
- text plus symbols for status; no meaning relies on color alone;
- local time with machine-readable ISO timestamps and UTC tooltip;
- polite freshness/loading regions and assertive denial/ambiguity/error announcements;
- reduced-motion and increased-contrast media queries;
- chart text alternative followed by an exact-value table;
- responsive layout down to 320 CSS pixels;
- review labels, digest text, typed confirmation, disabled and pending submit states;
- inert React text rendering for hostile evidence.

## Manual release checklist

- [ ] Complete every journey with keyboard only; no trap; logical focus order.
- [ ] Verify skip link and focus restoration after route, error, and tenant changes.
- [ ] Test 200%/400% zoom and reflow at 320 CSS pixels without lost controls.
- [ ] Verify normal/large text and focus contrast against WCAG 2.2 AA thresholds.
- [ ] Check VoiceOver/Safari, NVDA/Firefox, and JAWS/Chrome landmarks, tables, forms,
      live regions, status symbols, and validation.
- [ ] Confirm reduced motion, forced colors, dark/light OS settings, and offline state.
- [ ] Confirm server-time expiry is announced and cannot be bypassed with local clock.
- [ ] Confirm every chart has equivalent text/table data.
- [ ] Confirm ambiguous, denied, stale, quarantined, and failed are never announced as
      success.

Live assistive-technology and production-browser testing remains deferred.
