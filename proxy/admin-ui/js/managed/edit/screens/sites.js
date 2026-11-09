// The screen of the sites: the list of the sites, and one panel below the list that edits the site that is open (its
// name, its hosts and its certificate, which is either two files or ACME). What is typed goes to the draft, and nothing
// is saved here: the band above the form checks and saves it. The list is drawn again with every change and the panel is
// not, so that what is typed and the focus stay. What is in a file is never shown. Nothing runs when the module is
// loaded.

import { badge, button, el, mount } from '../../../dom.js';
import { lazy, t, w } from '../../../i18n.js';
import { bytesText, fingerprintView, panelWith } from '../../../parts.js';
import { Table } from '../../../table.js';
import { mountScreen } from '../../screen.js';
import { EditScreen } from '../bar.js';
import { siteFileKey } from '../draft.js';
import { fileBox, linesBox, numberBox, selectBox, textBox } from '../form.js';
import { linesOf } from '../items.js';
import { pemProblem, pickPem } from '../pem.js';

/** The marks of a site in the list: the tone of the badge, its words and the same words as text. */
const MARKS = {
  fresh: { tone: 'info', words: () => w('edit.mark.new'), text: () => t('edit.mark.new') },
  changed: { tone: 'warn', words: () => w('edit.mark.changed'), text: () => t('edit.mark.changed') },
  fault: { tone: 'bad', words: () => w('edit.mark.fault'), text: () => t('edit.mark.fault') },
};

/** The place that stays when the panel of a site is drawn again. */
const OUTSIDE_PANEL = new Set(['sites:notice']);

const nameOf = (site) => (site.name.trim() === '' ? w('edit.group.unnamed') : site.name.trim());

/** The hosts of a site as the list shows them: the first, and how many others there are. */
function hostsCell(site) {
  const hosts = linesOf(site.hosts).map((entry) => entry.text);
  if (hosts.length === 0) return '—';
  return hosts.length === 1 ? hosts[0] : w('edit.col.hosts_more', { first: hosts[0], n: hosts.length - 1 });
}

class SitesScreen extends EditScreen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.sites'), w('edit.sites.intro'), 'sites');
    /** The draft that the list was drawn from. */
    this.shown = null;
    /** What the lines of the list were last drawn from. */
    this.listKey = null;
    this.sitesNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.panelBox = el('div');
    /** The site whose panel is drawn, and what shows the chosen files of its certificate. */
    this.panelOf = null;
    this.filesShown = null;
    this.addButton = button('small', w('edit.sites.add'), () => this.addSite());
    this.table = new Table({
      caption: w('edit.sites.caption'),
      rowKey: (site) => String(site.cid),
      empty: { title: w('edit.sites.empty') },
      columns: [
        { key: 'name', label: w('edit.col.name'), value: (site) => site.name.trim(), mono: true, cell: (site) => nameOf(site) },
        { key: 'hosts', label: w('edit.col.hosts'), value: (site) => linesOf(site.hosts).map((entry) => entry.text).join(' '), mono: true, long: true, cell: (site) => hostsCell(site) },
        { key: 'certificate', label: w('edit.col.certificate'), value: (site) => site.kind, filter: false, cell: (site) => (site.kind === 'acme' ? w('edit.site.kind_acme') : w('edit.site.kind_file')) },
        { key: 'marks', label: w('col.state'), value: (site) => this.marksOf(site).map((name) => MARKS[name].text()).join(' '), cell: (site) => this.marksCell(site) },
        { key: 'actions', label: w('col.actions'), value: () => '', sortable: false, filter: false, cell: (site) => button('small', w('edit.upstreams.edit'), () => this.openSite(site.cid)) },
      ],
    });
    mount(this.form, panelWith(w('edit.sites.list_title'), [this.addButton], this.sitesNote, this.table.node).node, this.panelBox);
  }

  drawForm(draft) {
    this.places.clear();
    this.placeNote('sites', 'notice', this.sitesNote);
    this.listKey = null;
    this.drawPanel(draft);
  }

  drawList(draft) {
    this.shown = draft;
    // Only when a line would change: a drawing writes the count, which is read out, and takes the focus from a button of the list.
    const key = JSON.stringify(draft.sites.map((site) => [site.cid, site.name, site.hosts, site.kind, this.marksOf(site)]));
    if (key !== this.listKey) {
      this.listKey = key;
      this.table.update({ rows: draft.sites, loading: false });
    }
  }

  // ---- the list ----

  marksOf(site) {
    const draft = this.shown;
    const names = [];
    if (site.fresh) names.push('fresh');
    else if (draft.siteChanged(site)) names.push('changed');
    if (draft.faults.some((one) => one.panel === site.cid)) names.push('fault');
    return names;
  }

  marksCell(site) {
    const names = this.marksOf(site);
    return names.length === 0 ? null : el('span', { class: 'tc-badges' }, names.map((name) => badge(MARKS[name].tone, MARKS[name].words())));
  }

  addSite() {
    if (this.shown === null) return;
    this.openSite(this.shown.addSite().cid);
  }

  /** Opens the panel of the site `cid` and puts the focus on its name. */
  openSite(cid) {
    const draft = this.shown;
    draft.openPanels.sites = cid;
    this.drawPanel(draft);
    this.showFaults(draft);
    this.places.get(`${cid}:name`)?.box.control.focus();
  }

  closePanel(draft) {
    const cid = draft.openPanels.sites;
    draft.openPanels.sites = null;
    this.drawPanel(draft);
    if (!this.table.focusRow(String(cid))) this.root.querySelector('h1')?.focus();
  }

  // ---- the panel of a site ----

  drawPanel(draft) {
    for (const key of [...this.places.keys()]) {
      if (!OUTSIDE_PANEL.has(key)) this.places.delete(key);
    }
    const site = draft.site(draft.openPanels.sites);
    this.panelOf = site === null ? null : site.cid;
    this.filesShown = null;
    if (site === null) {
      mount(this.panelBox);
      return;
    }
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(site.cid, 'notice', note);
    const name = textBox(w('edit.site.name'), site.name, { required: true, hint: w('edit.group.name_hint'), onInput: (value) => draft.write(site, 'name', value) });
    this.placeField(site.cid, 'name', name);
    const hosts = linesBox(w('edit.site.hosts'), site.hosts, { required: true, hint: this.hostsHint(), onInput: (value) => draft.write(site, 'hosts', value) });
    this.placeField(site.cid, 'hosts', hosts);
    const remove = () => {
      draft.removeSite(site.cid);
      this.drawPanel(draft);
      this.root.querySelector('h1')?.focus();
    };
    mount(
      this.panelBox,
      panelWith(
        w('edit.site.title'),
        [button('small quiet', w('edit.group.close'), () => this.closePanel(draft))],
        note,
        el('div', { class: 'tc-fields' }, name.node, hosts.node),
        this.certificatePart(draft, site),
        el('div', { class: 'tc-actions' }, button('small danger', w('edit.site.remove'), remove)),
      ).node,
    );
  }

  /** Said only when the file was read and names the host of the route to this admin screen. */
  hostsHint() {
    const adminHost = this.data?.file?.adminHost ?? null;
    if (adminHost === null) return w('edit.site.hosts_hint');
    return lazy(() => `${t('edit.site.hosts_hint')} ${t('edit.admin_host', { host: adminHost })}`);
  }

  /** Opens the panel that holds the fault first: the first fault of the draft has made it the open one. */
  openFault(fault, draft) {
    if (fault.panel !== null && fault.panel !== this.panelOf) this.drawPanel(draft);
    super.openFault(fault, draft);
  }

  /** The part of a panel for the certificate: the choice of its kind, and the fields of that kind. */
  certificatePart(draft, site) {
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(site.cid, 'certificate', note);
    const fileShown = { chain: el('div', {}, this.fileView(draft, site.chain)), key: el('div', {}, this.fileView(draft, site.key)) };
    this.filesShown = { cid: site.cid, nodes: fileShown };
    const fileField = (field, label, hint) => {
      const box = fileBox(label, { hint, required: true, onFile: (file) => this.chooseFile(draft, site, field, file) });
      this.placeField(site.cid, field, box);
      return [box.node, fileShown[field]];
    };
    const files = el('div', { class: 'tc-fields' }, el('div', { class: 'tc-stack' }, fileField('chain', w('edit.site.chain'), w('edit.site.chain_hint'))), el('div', { class: 'tc-stack' }, fileField('key', w('edit.site.key'), w('edit.site.key_hint'))));
    const days = numberBox(w('edit.site.renew'), site.renew_before_days, { hint: this.renewHint(), onInput: (value) => draft.write(site, 'renew_before_days', value) });
    this.placeField(site.cid, 'renew_before_days', days);
    const acme = el('div', { class: 'tc-fields' }, days.node);
    const showKind = (kind) => {
      files.hidden = kind !== 'file';
      acme.hidden = kind !== 'acme';
    };
    const options = [
      { value: 'file', label: w('edit.site.kind_file') },
      { value: 'acme', label: w('edit.site.kind_acme') },
    ];
    const kind = selectBox(w('edit.site.kind'), options, site.kind, {
      onChange: (value) => {
        draft.setSiteKind(site, value);
        showKind(value);
        this.showFiles(draft, site);
      },
    });
    showKind(site.kind);
    return el('div', { class: 'tc-stack' }, el('h3', {}, w('edit.site.certificate')), note, el('div', { class: 'tc-fields' }, kind.node), files, acme);
  }

  /** Said only when the file was read and has no `acme`: a site with ACME is refused without it. */
  renewHint() {
    if (this.data?.file?.acme !== false) return w('edit.site.renew_hint');
    return lazy(() => `${t('edit.site.renew_hint')} ${t('edit.site.no_acme')}`);
  }

  /** What is known of a file of the certificate: the name and the size of one chosen here, and its fingerprint; never what is in it. */
  fileView(draft, sha256) {
    if (sha256 === '') return el('span', { class: 'tc-muted tc-small' }, w('edit.tls.ca_none'));
    const file = draft.files.get(sha256);
    return el('span', { class: 'tc-actions' }, file === undefined ? null : [el('span', { class: 'tc-mono' }, file.name), el('span', { class: 'tc-muted tc-small' }, bytesText(file.size))], fingerprintView(sha256, { copy: false }));
  }

  /** Shows what the open site now names, when the panel of `site` is the one shown. */
  showFiles(draft, site) {
    if (this.filesShown?.cid !== site.cid) return;
    mount(this.filesShown.nodes.chain, this.fileView(draft, site.chain));
    mount(this.filesShown.nodes.key, this.fileView(draft, site.key));
  }

  /** Reads a file of the certificate of `site`. What is wrong with it is a fault of the draft, and the panel that is shown by then shows what was chosen. */
  async chooseFile(draft, site, field, file) {
    const outcome = await pickPem(draft, siteFileKey(site.cid, field), file);
    if (outcome === null) return;
    if (outcome.problem !== undefined) {
      draft.putFault({ screen: 'sites', panel: site.cid, cid: site.cid, field, words: pemProblem(outcome.problem) });
      return;
    }
    draft.useFile(site, field, outcome.pem);
    this.showFiles(draft, site);
  }
}

export const screens = [{ id: 'sites', title: w('nav.sites'), least: 'operator', mount: mountScreen(SitesScreen) }];
