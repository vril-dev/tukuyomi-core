// The screen of the policy: the global access control and rate limit, which apply to every request but those of the
// route to this admin screen, and the host policies. A host policy holds, for the requests of its hosts, each of the two
// parts in one of three states: inherited from the global one, its own in the place of the global one, or not used. The
// list of the host policies is above one panel that edits the policy that is open. What is typed goes to the draft, and
// nothing is saved here: the band above the form checks and saves it. A global part can be turned off, and a part of a
// host policy can be put in another state, and what it holds stays in the draft meanwhile. The list is drawn again with
// every change and the panel is not, so that what is typed and the focus stay. Nothing runs when the module is loaded.

import { badge, button, el, mount, notice } from '../../../dom.js';
import { lazy, t, w } from '../../../i18n.js';
import { checkbox, choice, panelWith } from '../../../parts.js';
import { Table } from '../../../table.js';
import { mountScreen } from '../../screen.js';
import { EditScreen, unreachedNotice } from '../bar.js';
import { linesBox, numberBox, selectBox, textBox } from '../form.js';
import { linesOf } from '../items.js';

/** The marks of a host policy in the list: the tone of the badge, its words and the same words as text. */
const MARKS = {
  fresh: { tone: 'info', words: () => w('edit.mark.new'), text: () => t('edit.mark.new') },
  changed: { tone: 'warn', words: () => w('edit.mark.changed'), text: () => t('edit.mark.changed') },
  fault: { tone: 'bad', words: () => w('edit.mark.fault'), text: () => t('edit.mark.fault') },
};

/** The states of a part of a host policy, in the order of its choice. */
const MODES = {
  inherit: () => w('edit.host.inherit'),
  own: () => w('edit.host.own'),
  off: () => w('edit.host.off'),
};

/** What each state of a part does, for the access control (`access`) and for the rate limit (`rate`). */
const MODE_HINTS = {
  access: { inherit: () => w('edit.host.access_inherit'), own: () => w('edit.host.access_own'), off: () => w('edit.host.access_off') },
  rate: { inherit: () => w('edit.host.rate_inherit'), own: () => w('edit.host.rate_own'), off: () => w('edit.host.rate_off') },
};

/** The items whose places stay when the panel of a host policy is drawn again: the global parts and the list. */
const OUTSIDE_PANEL = new Set(['access', 'rate', 'host_policies']);

const nameOf = (policy) => (policy.name.trim() === '' ? w('edit.group.unnamed') : policy.name.trim());

/** The hosts of a host policy as the list shows them: the first, and how many others there are. */
function hostsCell(policy) {
  const hosts = linesOf(policy.hosts).map((entry) => entry.text);
  if (hosts.length === 0) return '—';
  return hosts.length === 1 ? hosts[0] : w('edit.col.hosts_more', { first: hosts[0], n: hosts.length - 1 });
}

class PolicyScreen extends EditScreen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.policy'), w('edit.policy.intro'), 'policy');
    this.accessNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.accessBox = el('div', { class: 'tc-stack' });
    this.rateNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.rateBox = el('div', { class: 'tc-stack' });
    /** What a change of each global part says of the host policies that it does not reach. */
    this.accessReach = el('div');
    this.rateReach = el('div');
    /** The draft that the list was drawn from, what the lines of the list were last drawn from, and the names that the notice of each global part was last drawn from. */
    this.shown = null;
    this.listKey = null;
    this.reachKeys = { access: null, rate_limit: null };
    this.hostsNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.panelBox = el('div');
    /** The host policy whose panel is drawn. */
    this.panelOf = null;
    this.addButton = button('small', w('edit.hosts.add'), () => this.addHostPolicy());
    this.table = new Table({
      caption: w('edit.hosts.caption'),
      rowKey: (policy) => String(policy.cid),
      empty: { title: w('edit.hosts.empty') },
      fold: true,
      columns: [
        { key: 'name', label: w('edit.col.name'), value: (policy) => policy.name.trim(), mono: true, long: true, cell: (policy) => nameOf(policy) },
        { key: 'hosts', label: w('edit.col.hosts'), value: (policy) => linesOf(policy.hosts).map((entry) => entry.text).join(' '), mono: true, long: true, cell: (policy) => hostsCell(policy) },
        { key: 'access', label: w('edit.access.title'), value: (policy) => policy.access.mode, filter: false, cell: (policy) => MODES[policy.access.mode]() },
        { key: 'rate', label: w('edit.rate.title'), value: (policy) => policy.rate.mode, filter: false, cell: (policy) => MODES[policy.rate.mode]() },
        { key: 'marks', label: w('col.state'), value: (policy) => this.marksOf(policy).map((name) => MARKS[name].text()).join(' '), cell: (policy) => this.marksCell(policy) },
        { key: 'actions', label: w('col.actions'), value: () => '', sortable: false, filter: false, cell: (policy) => button('small', w('edit.upstreams.edit'), () => this.openHostPolicy(policy.cid)) },
      ],
    });
    mount(
      this.form,
      notice('info', w('edit.policy.not_admin_route')),
      panelWith(w('edit.area.access'), [], this.accessNote, this.accessReach, this.accessBox).node,
      panelWith(w('edit.area.rate_limit'), [], this.rateNote, this.rateReach, this.rateBox).node,
      panelWith(w('edit.hosts.list_title'), [this.addButton], el('p', { class: 'tc-muted tc-small' }, w('edit.hosts.hint')), this.hostsNote, this.table.node).node,
      this.panelBox,
    );
  }

  drawForm(draft) {
    this.places.clear();
    this.placeNote('access', 'notice', this.accessNote);
    this.placeNote('rate', 'notice', this.rateNote);
    this.placeNote('host_policies', 'notice', this.hostsNote);
    this.drawAccess(draft);
    this.drawRate(draft);
    this.listKey = null;
    this.reachKeys = { access: null, rate_limit: null };
    this.drawPanel(draft);
  }

  drawList(draft) {
    this.shown = draft;
    // Only when a line would change: a drawing writes the count, which is read out, and takes the focus from a button of the list.
    const key = JSON.stringify(draft.hostPolicies.map((policy) => [policy.cid, policy.name, policy.hosts, policy.access.mode, policy.rate.mode, this.marksOf(policy)]));
    if (key !== this.listKey) {
      this.listKey = key;
      this.table.update({ rows: draft.hostPolicies, loading: false });
    }
    // The same for the notice of what a change of each global part does not reach, which is read out as well: each is
    // drawn again only when the names that it gives, and so their number, change.
    for (const [kind, box] of [
      ['access', this.accessReach],
      ['rate_limit', this.rateReach],
    ]) {
      const names = draft.unreached(kind);
      const reachKey = JSON.stringify(names);
      if (reachKey === this.reachKeys[kind]) continue;
      this.reachKeys[kind] = reachKey;
      mount(box, unreachedNotice(kind, names));
    }
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
    const lists = el('div', { class: 'tc-fields tc-fields--two' });
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
    const fields = el('div', { class: 'tc-fields tc-fields--two' });
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

  // ---- the list of the host policies ----

  marksOf(policy) {
    const draft = this.shown;
    const names = [];
    if (policy.fresh) names.push('fresh');
    else if (draft.hostPolicyChanged(policy)) names.push('changed');
    if (draft.faults.some((one) => one.panel === policy.cid)) names.push('fault');
    return names;
  }

  marksCell(policy) {
    const names = this.marksOf(policy);
    return names.length === 0 ? null : el('span', { class: 'tc-badges' }, names.map((name) => badge(MARKS[name].tone, MARKS[name].words())));
  }

  addHostPolicy() {
    if (this.shown === null) return;
    this.openHostPolicy(this.shown.addHostPolicy().cid);
  }

  /** Opens the panel of the host policy `cid` and puts the focus on its name. */
  openHostPolicy(cid) {
    const draft = this.shown;
    draft.openPanels.policy = cid;
    this.drawPanel(draft);
    this.showFaults(draft);
    this.places.get(`${cid}:name`)?.box.control.focus();
  }

  closePanel(draft) {
    const cid = draft.openPanels.policy;
    draft.openPanels.policy = null;
    this.drawPanel(draft);
    if (!this.table.focusRow(String(cid))) this.root.querySelector('h1')?.focus();
  }

  // ---- the panel of a host policy ----

  drawPanel(draft) {
    for (const [key, place] of [...this.places]) {
      if (!OUTSIDE_PANEL.has(place.cid)) this.places.delete(key);
    }
    const policy = draft.hostPolicy(draft.openPanels.policy);
    this.panelOf = policy === null ? null : policy.cid;
    if (policy === null) {
      mount(this.panelBox);
      return;
    }
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(policy.cid, 'notice', note);
    const name = textBox(w('edit.site.name'), policy.name, { required: true, hint: w('edit.group.name_hint'), onInput: (value) => draft.write(policy, 'name', value) });
    this.placeField(policy.cid, 'name', name);
    const hosts = linesBox(w('edit.site.hosts'), policy.hosts, { required: true, hint: this.hostsHint(), onInput: (value) => draft.write(policy, 'hosts', value) });
    this.placeField(policy.cid, 'hosts', hosts);
    const remove = () => {
      draft.removeHostPolicy(policy.cid);
      this.drawPanel(draft);
      this.root.querySelector('h1')?.focus();
    };
    mount(
      this.panelBox,
      panelWith(
        w('edit.host.title'),
        [button('small quiet', w('edit.group.close'), () => this.closePanel(draft))],
        note,
        el('div', { class: 'tc-fields' }, name.node, hosts.node),
        this.accessPart(draft, policy),
        this.ratePart(draft, policy),
        el('div', { class: 'tc-actions' }, button('small danger', w('edit.host.remove'), remove)),
      ).node,
    );
  }

  /** Said only when the file was read and names the host of the route to this admin screen. */
  hostsHint() {
    const adminHost = this.data?.file?.adminHost ?? null;
    if (adminHost === null) return w('edit.host.hosts_hint');
    return lazy(() => `${t('edit.host.hosts_hint')} ${t('edit.admin_host', { host: adminHost })}`);
  }

  /** Opens the panel that holds the fault first: the first fault of the draft has made it the open one. */
  openFault(fault, draft) {
    if (fault.panel !== null && fault.panel !== this.panelOf) this.drawPanel(draft);
    super.openFault(fault, draft);
  }

  /** The choice of the state of the part `part` (`access` or `rate`) of `policy`, with what the state does said below it; `fields` are shown in its own state only. */
  modeChoice(draft, policy, part, label, fields) {
    const item = policy[part];
    const said = el('span', {}, MODE_HINTS[part][item.mode]());
    fields.hidden = item.mode !== 'own';
    const options = Object.entries(MODES).map(([mode, words]) => ({ value: mode, label: words() }));
    const box = selectBox(label, options, item.mode, {
      hint: said,
      onChange: (value) => {
        draft.setHostMode(policy, part, value);
        fields.hidden = value !== 'own';
        mount(said, MODE_HINTS[part][value]());
      },
    });
    return box.node;
  }

  /** The part of a panel for the access control: the choice of its state, and the four lists of its own state. */
  accessPart(draft, policy) {
    const { access } = policy;
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(access.cid, 'notice', note);
    const list = (key, label, hint) => {
      const box = linesBox(label, access[key], { hint, onInput: (value) => draft.write(access, key, value) });
      this.placeField(access.cid, key, box);
      return box.node;
    };
    // Said only when the file was read and has no country database: a list of countries is refused without one.
    const countryHint = this.data?.file?.geo === false ? w('edit.access.no_geo') : null;
    const lists = el(
      'div',
      { class: 'tc-fields tc-fields--two' },
      list('deny_cidrs', w('edit.access.deny_cidrs'), w('edit.access.networks_hint')),
      list('allow_cidrs', w('edit.access.allow_cidrs'), w('edit.access.networks_hint')),
      list('deny_countries', w('edit.access.deny_countries'), countryHint),
      list('allow_countries', w('edit.access.allow_countries'), countryHint),
    );
    return el('div', { class: 'tc-stack' }, el('h3', {}, w('edit.access.title')), note, el('div', { class: 'tc-fields' }, this.modeChoice(draft, policy, 'access', w('edit.access.title'), lists)), lists);
  }

  /** The part of a panel for the rate limit: the choice of its state, and the numbers and the list of its own state. */
  ratePart(draft, policy) {
    const { rate } = policy;
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(rate.cid, 'notice', note);
    const number = (key, label, hint) => {
      const box = numberBox(label, rate[key], { hint, onInput: (value) => draft.write(rate, key, value) });
      this.placeField(rate.cid, key, box);
      return box.node;
    };
    const exempt = linesBox(w('edit.rate.exempt'), rate.exempt_cidrs, { hint: w('edit.access.networks_hint'), onInput: (value) => draft.write(rate, 'exempt_cidrs', value) });
    this.placeField(rate.cid, 'exempt_cidrs', exempt);
    const fields = el(
      'div',
      { class: 'tc-fields tc-fields--two' },
      number('rate', w('edit.rate.rate'), w('edit.rate.rate_hint')),
      number('burst', w('edit.rate.burst'), w('edit.rate.burst_hint')),
      number('keys', w('edit.rate.keys'), w('edit.host.keys_hint')),
      exempt.node,
    );
    return el('div', { class: 'tc-stack' }, el('h3', {}, w('edit.rate.title')), note, el('div', { class: 'tc-fields' }, this.modeChoice(draft, policy, 'rate', w('edit.rate.title'), fields)), fields);
  }
}

export const screens = [{ id: 'policy', title: w('nav.policy'), least: 'operator', mount: mountScreen(PolicyScreen) }];
