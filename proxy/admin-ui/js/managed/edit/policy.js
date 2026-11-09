// The screen of the global policy: the access control and the rate limit that apply to every request but those of the
// route to this admin screen. What is typed goes to the draft, and nothing is saved here: the band above the form checks
// and saves it. Each part can be turned off, and what it holds stays in the draft meanwhile. Nothing runs when the module
// is loaded.

import { el, mount, notice } from '../../dom.js';
import { w } from '../../i18n.js';
import { checkbox, choice, panelWith } from '../../parts.js';
import { mountScreen } from '../screen.js';
import { EditScreen } from './bar.js';
import { linesBox, numberBox } from './form.js';

class PolicyScreen extends EditScreen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.policy'), w('edit.policy.intro'), 'policy');
    this.accessNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.accessBox = el('div', { class: 'tc-stack' });
    this.rateNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.rateBox = el('div', { class: 'tc-stack' });
    mount(this.form, notice('info', w('edit.policy.not_admin_route')), panelWith(w('edit.access.title'), [], this.accessNote, this.accessBox).node, panelWith(w('edit.rate.title'), [], this.rateNote, this.rateBox).node);
  }

  drawForm(draft) {
    this.places.clear();
    this.placeNote('access', 'notice', this.accessNote);
    this.placeNote('rate', 'notice', this.rateNote);
    this.drawAccess(draft);
    this.drawRate(draft);
  }

  /** The switch of a part of the policy, and what it shows and hides. */
  partSwitch(draft, item, label, box) {
    box.hidden = !item.on;
    const use = checkbox((checked) => {
      draft.write(item, 'on', checked);
      box.hidden = !checked;
      // What is hidden cannot be corrected.
      if (!checked) draft.clearFaultsOf(item.cid);
    });
    use.checked = item.on;
    return choice(label, use);
  }

  drawAccess(draft) {
    const { access } = draft;
    const lists = el('div', { class: 'tc-fields' });
    const list = (key, label, hint) => {
      const box = linesBox(label, access[key], { hint, onInput: (value) => draft.write(access, key, value) });
      this.placeField('access', key, box);
      return box.node;
    };
    // Said only when the file was read and has no country database: a list of countries is refused without one.
    const countryHint = this.data?.file?.geo === false ? w('edit.access.no_geo') : null;
    mount(
      lists,
      list('deny_cidrs', w('edit.access.deny_cidrs'), w('edit.access.networks_hint')),
      list('allow_cidrs', w('edit.access.allow_cidrs'), w('edit.access.networks_hint')),
      list('deny_countries', w('edit.access.deny_countries'), countryHint),
      list('allow_countries', w('edit.access.allow_countries'), countryHint),
    );
    mount(this.accessBox, this.partSwitch(draft, access, w('edit.access.use'), lists), lists);
  }

  drawRate(draft) {
    const { rate } = draft;
    const fields = el('div', { class: 'tc-fields' });
    const number = (key, label, hint) => {
      const box = numberBox(label, rate[key], { hint, onInput: (value) => draft.write(rate, key, value) });
      this.placeField('rate', key, box);
      return box.node;
    };
    const exempt = linesBox(w('edit.rate.exempt'), rate.exempt_cidrs, { hint: w('edit.access.networks_hint'), onInput: (value) => draft.write(rate, 'exempt_cidrs', value) });
    this.placeField('rate', 'exempt_cidrs', exempt);
    mount(fields, number('rate', w('edit.rate.rate'), w('edit.rate.rate_hint')), number('burst', w('edit.rate.burst'), w('edit.rate.burst_hint')), number('keys', w('edit.rate.keys'), w('edit.rate.keys_hint')), exempt.node);
    mount(this.rateBox, this.partSwitch(draft, rate, w('edit.rate.use'), fields), fields);
  }
}

export const screens = [{ id: 'policy', title: w('nav.policy'), least: 'operator', mount: mountScreen(PolicyScreen) }];
