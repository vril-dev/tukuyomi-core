// The screen of the upstream groups: the default group, the list of the groups, and one panel below the list that edits
// the group that is open (its servers, and TLS with the file of its authorities). What is typed goes to the draft, and
// nothing is saved here: the band above the form checks and saves it. The list is drawn again with every change and the
// panel is not, so that what is typed and the focus stay. Nothing runs when the module is loaded.

import { badge, button, el, mount } from '../../../dom.js';
import { t, w } from '../../../i18n.js';
import { bytesText, checkbox, choice, fingerprintView, panelWith } from '../../../parts.js';
import { Table } from '../../../table.js';
import { mountScreen } from '../../screen.js';
import { EditScreen } from '../bar.js';
import { caKey } from '../draft.js';
import { Rows, fileBox, numberBox, selectBox, textBox } from '../form.js';
import { pemProblem, pickPem } from '../pem.js';

/** The marks of a group in the list: the tone of the badge, its words and the same words as text. */
const MARKS = {
  default: { tone: 'info', words: () => w('edit.mark.default'), text: () => t('edit.mark.default') },
  fresh: { tone: 'info', words: () => w('edit.mark.new'), text: () => t('edit.mark.new') },
  changed: { tone: 'warn', words: () => w('edit.mark.changed'), text: () => t('edit.mark.changed') },
  fault: { tone: 'bad', words: () => w('edit.mark.fault'), text: () => t('edit.mark.fault') },
};

/** The places that stay when the panel of a group is drawn again. */
const OUTSIDE_PANEL = new Set(['default:default', 'groups:notice']);
const SERVER_FIELDS = ['address', 'weight', 'max_fails', 'fail_timeout_ms'];

const nameOf = (group) => (group.name.trim() === '' ? w('edit.group.unnamed') : group.name.trim());

class UpstreamsScreen extends EditScreen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.upstreams'), w('edit.upstreams.intro'), 'upstreams');
    /** The draft that the list was drawn from. */
    this.shown = null;
    this.defaultBox = el('div');
    /** The choice of the default group, and the groups that it was last drawn from. */
    this.defaultField = null;
    this.defaultKey = null;
    /** What the lines of the list were last drawn from. */
    this.listKey = null;
    this.groupsNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.panelBox = el('div');
    /** The group whose panel is drawn, what shows the file of its authorities, the rows of its servers, and the part with its button that takes it away. */
    this.panelOf = null;
    this.caShown = null;
    this.rows = null;
    this.removeBox = null;
    this.removeKey = null;
    this.addButton = button('small', w('edit.upstreams.add'), () => this.addGroup());
    this.table = new Table({
      caption: w('edit.upstreams.caption'),
      rowKey: (group) => String(group.cid),
      empty: { title: w('edit.upstreams.empty') },
      columns: [
        { key: 'name', label: w('edit.col.name'), value: (group) => group.name.trim(), mono: true, cell: (group) => nameOf(group) },
        { key: 'servers', label: w('edit.col.servers'), value: (group) => group.servers.length, num: true, filter: false },
        { key: 'tls', label: w('edit.col.tls'), value: (group) => (group.tls ? 1 : 0), filter: false, cell: (group) => (group.tls ? w('edit.col.tls_on') : '—') },
        { key: 'routes', label: w('edit.col.routes'), value: (group) => this.shown.uses(group.cid).routes, num: true, filter: false },
        { key: 'marks', label: w('col.state'), value: (group) => this.marksOf(group).map((name) => MARKS[name].text()).join(' '), cell: (group) => this.marksCell(group) },
        { key: 'actions', label: w('col.actions'), value: () => '', sortable: false, filter: false, cell: (group) => button('small', w('edit.upstreams.edit'), () => this.openGroup(group.cid)) },
      ],
    });
    mount(this.form, panelWith(w('edit.upstreams.default_title'), [], this.defaultBox).node, panelWith(w('edit.upstreams.list_title'), [this.addButton], this.groupsNote, this.table.node).node, this.panelBox);
  }

  drawForm(draft) {
    this.places.clear();
    this.placeNote('groups', 'notice', this.groupsNote);
    this.defaultKey = null;
    this.listKey = null;
    this.drawPanel(draft);
  }

  drawList(draft) {
    this.shown = draft;
    this.drawDefault(draft);
    // Only when a line would change: a drawing writes the count, which is read out, and takes the focus from a button of the list.
    const key = JSON.stringify(draft.groups.map((group) => [group.cid, group.name, group.servers.length, group.tls, draft.uses(group.cid).routes, this.marksOf(group)]));
    if (key !== this.listKey) {
      this.listKey = key;
      this.table.update({ rows: draft.groups, loading: false });
    }
    this.drawRemove(draft);
  }

  // ---- the default group ----

  /** The choice of the default group; made again only when a group has changed, and the focus moves to the new one. */
  drawDefault(draft) {
    const key = JSON.stringify(draft.groups.map((group) => [group.cid, group.name]));
    if (key === this.defaultKey) return;
    this.defaultKey = key;
    const focused = this.defaultField !== null && globalThis.document.activeElement === this.defaultField.control;
    const options = [{ value: '', label: w('edit.upstreams.no_default') }, ...draft.groups.map((group) => ({ value: group.cid, label: nameOf(group) }))];
    this.defaultField = selectBox(w('edit.upstreams.default'), options, draft.defaultRef.cid ?? '', { onChange: (value) => draft.setDefault(value) });
    this.placeField('default', 'default', this.defaultField);
    mount(this.defaultBox, this.defaultField.node);
    if (focused) this.defaultField.control.focus();
  }

  // ---- the list ----

  marksOf(group) {
    const draft = this.shown;
    const names = [];
    if (draft.defaultRef.cid === group.cid) names.push('default');
    if (group.fresh) names.push('fresh');
    else if (draft.groupChanged(group)) names.push('changed');
    if (draft.faults.some((one) => one.panel === group.cid)) names.push('fault');
    return names;
  }

  marksCell(group) {
    const names = this.marksOf(group);
    return names.length === 0 ? null : el('span', { class: 'tc-badges' }, names.map((name) => badge(MARKS[name].tone, MARKS[name].words())));
  }

  addGroup() {
    if (this.shown === null) return;
    this.openGroup(this.shown.addGroup().cid);
  }

  /** Opens the panel of the group `cid` and puts the focus on its name. */
  openGroup(cid) {
    const draft = this.shown;
    draft.openPanels.upstreams = cid;
    this.drawPanel(draft);
    this.showFaults(draft);
    this.places.get(`${cid}:name`)?.box.control.focus();
  }

  closePanel(draft) {
    const cid = draft.openPanels.upstreams;
    draft.openPanels.upstreams = null;
    this.drawPanel(draft);
    if (!this.table.focusRow(String(cid))) this.root.querySelector('h1')?.focus();
  }

  // ---- the panel of a group ----

  drawPanel(draft) {
    for (const key of [...this.places.keys()]) {
      if (!OUTSIDE_PANEL.has(key)) this.places.delete(key);
    }
    const group = draft.group(draft.openPanels.upstreams);
    this.panelOf = group === null ? null : group.cid;
    this.caShown = null;
    this.removeKey = null;
    if (group === null) {
      this.rows = null;
      this.removeBox = null;
      mount(this.panelBox);
      return;
    }
    const name = textBox(w('edit.group.name'), group.name, { required: true, hint: w('edit.group.name_hint'), onInput: (value) => draft.write(group, 'name', value) });
    this.placeField(group.cid, 'name', name);
    const serversNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(group.cid, 'servers', serversNote);
    this.rows = new Rows();
    for (const server of group.servers) this.rows.add(this.serverLine(draft, group, server));
    this.removeBox = el('div', { class: 'tc-actions' });
    mount(
      this.panelBox,
      panelWith(
        w('edit.group.title'),
        [button('small quiet', w('edit.group.close'), () => this.closePanel(draft))],
        name.node,
        el('h3', {}, w('edit.group.servers')),
        serversNote,
        this.rows.node,
        el('div', { class: 'tc-actions' }, button('small', w('edit.server.add'), () => this.addServer(draft, group))),
        this.tlsPart(draft, group),
        this.removeBox,
      ).node,
    );
    this.drawRemove(draft);
  }

  /** Opens the panel that holds the fault first: the first fault of the draft has made it the open one. */
  openFault(fault, draft) {
    if (fault.panel !== null && fault.panel !== this.panelOf) this.drawPanel(draft);
    super.openFault(fault, draft);
  }

  serverLine(draft, group, server) {
    const input = (key) => (value) => draft.write(server, key, value);
    const address = textBox(w('edit.server.address'), server.address, { required: true, hint: w('edit.server.address_hint'), placeholder: '192.0.2.10:8080', onInput: input('address') });
    const weight = numberBox(w('edit.server.weight'), server.weight, { hint: w('edit.server.weight_hint'), onInput: input('weight') });
    const maxFails = numberBox(w('edit.server.max_fails'), server.max_fails, { hint: w('edit.server.max_fails_hint'), onInput: input('max_fails') });
    const timeout = numberBox(w('edit.server.fail_timeout'), server.fail_timeout_ms, { hint: w('edit.server.fail_timeout_hint'), onInput: input('fail_timeout_ms') });
    this.placeField(server.cid, 'address', address);
    this.placeField(server.cid, 'weight', weight);
    this.placeField(server.cid, 'max_fails', maxFails);
    this.placeField(server.cid, 'fail_timeout_ms', timeout);
    const backup = checkbox((checked) => draft.write(server, 'backup', checked));
    backup.checked = server.backup;
    const line = { node: null, address };
    const remove = button('small quiet', w('edit.server.remove'), () => {
      draft.removeServer(group, server.cid);
      for (const field of SERVER_FIELDS) this.places.delete(`${server.cid}:${field}`);
      this.rows.remove(line);
    });
    line.node = el('div', { class: 'tc-rows__row tc-rows__row--server' }, address.node, weight.node, maxFails.node, timeout.node, choice(w('edit.server.backup'), backup), remove);
    return line;
  }

  addServer(draft, group) {
    const line = this.serverLine(draft, group, draft.addServer(group));
    this.rows.add(line);
    this.showFaults(draft);
    line.address.control.focus();
  }

  /** The part of a panel for TLS. Turned off, what it holds stays in the draft. */
  tlsPart(draft, group) {
    const box = el('div', { class: 'tc-stack' });
    box.hidden = !group.tls;
    const use = checkbox((checked) => {
      draft.write(group, 'tls', checked);
      box.hidden = !checked;
      if (checked) return;
      // What is hidden cannot be corrected.
      draft.clearFault(group.cid, 'ca');
      draft.clearFault(group.cid, 'server_name');
    });
    use.checked = group.tls;
    const chosen = el('div', {}, this.caView(draft, group));
    this.caShown = { cid: group.cid, node: chosen };
    const ca = fileBox(w('edit.tls.choose'), { hint: w('edit.tls.ca_hint'), onFile: (file) => this.chooseCa(draft, group, file) });
    this.placeField(group.cid, 'ca', ca);
    const serverName = textBox(w('edit.tls.server_name'), group.server_name, { hint: w('edit.tls.server_name_hint'), onInput: (value) => draft.write(group, 'server_name', value) });
    this.placeField(group.cid, 'server_name', serverName);
    mount(box, ca.node, chosen, serverName.node);
    return el('div', { class: 'tc-stack' }, choice(w('edit.tls.use'), use, w('edit.tls.use_hint')), box);
  }

  /** What is known of the file of the authorities of a group: the name and the size of one chosen here, and its fingerprint; never what is in it. */
  caView(draft, group) {
    if (group.ca === '') return el('span', { class: 'tc-muted tc-small' }, w('edit.tls.ca_none'));
    const file = draft.files.get(group.ca);
    return el('span', { class: 'tc-actions' }, file === undefined ? null : [el('span', { class: 'tc-mono' }, file.name), el('span', { class: 'tc-muted tc-small' }, bytesText(file.size))], fingerprintView(group.ca, { copy: false }));
  }

  /** Reads the file of the authorities of `group`. What is wrong with it is a fault of the draft, and the panel that is shown by then shows what was chosen. */
  async chooseCa(draft, group, file) {
    const outcome = await pickPem(draft, caKey(group.cid), file);
    if (outcome === null) return;
    if (outcome.problem !== undefined) {
      draft.putFault({ screen: 'upstreams', panel: group.cid, cid: group.cid, field: 'ca', words: pemProblem(outcome.problem) });
      return;
    }
    draft.useFile(group, 'ca', outcome.pem);
    if (this.caShown?.cid === group.cid) mount(this.caShown.node, this.caView(draft, group));
  }

  /** The button that takes the open group away, or why it cannot; drawn again only when that changes, so that it keeps the focus. */
  drawRemove(draft) {
    const group = draft.group(this.panelOf);
    if (group === null || this.removeBox === null) return;
    const { routes, isDefault } = draft.uses(group.cid);
    const last = draft.groups.length === 1;
    const key = `${routes} ${isDefault} ${last}`;
    if (key === this.removeKey) return;
    this.removeKey = key;
    let why = null;
    if (routes > 0) why = w('edit.group.used_by_routes', { n: routes });
    else if (isDefault) why = w('edit.group.is_default');
    else if (last) why = w('edit.group.last');
    const remove = () => {
      if (!draft.removeGroup(group.cid)) return;
      this.drawPanel(draft);
      this.root.querySelector('h1')?.focus();
    };
    mount(this.removeBox, button('small danger', w('edit.group.remove'), remove, { disabled: why !== null }), why === null ? null : el('span', { class: 'tc-muted tc-small' }, why));
  }
}

export const screens = [{ id: 'upstreams', title: w('nav.upstreams'), least: 'operator', mount: mountScreen(UpstreamsScreen) }];
