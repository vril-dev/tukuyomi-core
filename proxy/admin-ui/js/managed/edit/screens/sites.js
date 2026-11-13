// The screen of the sites: the list of the sites, and one panel below the list that edits the site that is open (its
// name, its hosts and its certificate, which is either two files or ACME). What is typed goes to the draft, and nothing
// is saved here: the band above the form checks and saves it. The list is drawn again with every change and the panel is
// not, so that what is typed and the focus stay. What is in a file is never shown. The list and the panel also show
// what the managed store holds of the certificate that a site names (its expiry, its state and the host names in it),
// matched by what is in the certificate. Nothing runs when the module is loaded.

import { badge, button, el, mount } from '../../../dom.js';
import { lazy, t, w } from '../../../i18n.js';
import { bytesText, fingerprintView, isFingerprint, kv, panelWith, row, timeCellText, timeLabel, timeView } from '../../../parts.js';
import { Table } from '../../../table.js';
import { certificateBadge, certificateExpiry, certificateText, expiryCell, mountScreen } from '../../screen.js';
import { EditScreen } from '../bar.js';
import { hostsKey } from '../changes.js';
import { heldDraft, siteFileKey } from '../draft.js';
import { fileBox, linesBox, numberBox, selectBox, textBox } from '../form.js';
import { linesOf, texts } from '../items.js';
import { pemProblem, pickPem } from '../pem.js';

/** The marks of a site in the list: the tone of the badge, its words and the same words as text. */
const MARKS = {
  fresh: { tone: 'info', words: () => w('edit.mark.new'), text: () => t('edit.mark.new') },
  changed: { tone: 'warn', words: () => w('edit.mark.changed'), text: () => t('edit.mark.changed') },
  fault: { tone: 'bad', words: () => w('edit.mark.fault'), text: () => t('edit.mark.fault') },
};

/** The place that stays when the panel of a site is drawn again. */
const OUTSIDE_PANEL = new Set(['sites:notice']);

/** The states of a certificate that the list marks with nothing: it is there. */
const THERE = new Set(['present', 'issued']);

const nameOf = (site) => (site.name.trim() === '' ? w('edit.group.unnamed') : site.name.trim());

/** The hosts of a site as the list shows them: the first, and how many others there are. */
function hostsCell(site) {
  const hosts = linesOf(site.hosts).map((entry) => entry.text);
  if (hosts.length === 0) return '—';
  return hosts.length === 1 ? hosts[0] : w('edit.col.hosts_more', { first: hosts[0], n: hosts.length - 1 });
}

/**
 * The answers of `GET /api/managed/certificates/<name>` (null: not read) put in order to be matched with the sites of
 * the draft: a site with ACME by the set of its hosts, and a site of files by its chain, with every site of the answers
 * that has that chain (those of the first answer first).
 */
export function certificateIndex(answers) {
  const acme = new Map();
  const chains = new Map();
  for (const answer of answers) {
    if (answer === null) continue;
    for (const site of answer.sites) {
      if (site.kind === 'acme' && texts(site.hosts) && site.hosts.length > 0) {
        const key = hostsKey(site);
        if (!acme.has(key)) acme.set(key, site);
      } else if (site.kind === 'files' && isFingerprint(site.chain) && isFingerprint(site.key)) {
        if (!chains.has(site.chain)) chains.set(site.chain, []);
        chains.get(site.chain).push(site);
      }
    }
  }
  return { acme, chains };
}

/**
 * What the managed store holds of the certificate that the site `site` of the draft names now, from `index` (see
 * `certificateIndex`; null: nothing was read): `{ answer, whole }`, or null when no site of the answers has the same
 * certificate. A certificate is matched by what is in it and not by the name or the place of its site: with ACME by the
 * set of the hosts, with files by the chain. Its expiry and its names follow from the chain alone and its state from the
 * key too, so `whole` says that the key is the same as well (always with ACME: the set of the hosts names both files).
 */
export function certificateOf(site, index) {
  if (index === null) return null;
  if (site.kind === 'acme') {
    const hosts = linesOf(site.hosts).map((entry) => entry.text);
    const answer = hosts.length === 0 ? undefined : index.acme.get(hostsKey({ hosts }));
    return answer === undefined ? null : { answer, whole: true };
  }
  const answers = index.chains.get(site.chain) ?? [];
  const whole = answers.find((one) => one.key === site.key);
  if (whole !== undefined) return { answer: whole, whole: true };
  return answers.length === 0 ? null : { answer: answers[0], whole: false };
}

/** The badge of the list for the state `state` of a certificate (null: not shown), or null for one that is there. */
const listedMark = (state) => (state === null || THERE.has(state) ? null : certificateBadge(state));

/** The cell of the expiry of a site in the list, from what `listed` gives. */
function expiresCell(shown) {
  return shown === null ? '—' : expiryCell(shown, listedMark(shown.state));
}

/** The text of `expiresCell`, for the filter of the list. */
function expiresText(shown) {
  if (shown === null) return '';
  return [shown.notAfter === null ? '' : timeCellText(shown.notAfter, 's'), shown.expired ? t('managed.cert.expired') : '', listedMark(shown.state) === null ? '' : certificateText(shown.state)].join(' ');
}

/** The host names in a certificate: those that the answer gives and how many more there are, or null when the answer has none because they could not be read. */
function namesView(answer) {
  if (!Array.isArray(answer.names)) return null;
  const names = answer.names.filter((name) => typeof name === 'string');
  const more = Number.isSafeInteger(answer.more) && answer.more > 0 ? answer.more : 0;
  if (names.length === 0 && more === 0) return w('edit.site.cert_no_names');
  return [names.length === 0 ? null : el('span', { class: 'tc-mono' }, names.join(', ')), names.length > 0 && more > 0 ? ' ' : null, more > 0 ? w('edit.site.cert_more', { n: more }) : null];
}

/** What the panel says of a certificate that could not be parsed: for a site with ACME only of the expiry, as its panel shows no names. */
function unreadWords(answer, acme, notAfter) {
  if (answer.state !== 'unparsed') return null;
  if (acme) return notAfter === null ? w('edit.site.cert_unread_expiry') : null;
  return notAfter === null ? w('edit.site.cert_unread_all') : w('edit.site.cert_unread_names');
}

/**
 * What the panel of a site shows of its certificate in the managed store, from what `certificateOf` found: its state
 * (only when the key is the same too, and for files only when something is wrong), the host names in it, its expiry, and
 * that this is the file in the store and not what the proxy has read. Nothing is shown when nothing of it is known.
 */
function certificateView({ answer, whole }) {
  const acme = answer.kind === 'acme';
  const { notAfter, expired } = certificateExpiry(answer);
  const unread = unreadWords(answer, acme, notAfter);
  const names = acme ? null : namesView(answer);
  const rows = [];
  if (whole && (acme || !THERE.has(answer.state))) rows.push(row(w('col.state'), certificateBadge(answer.state)));
  if (names !== null) rows.push(row(w('edit.site.cert_names'), names));
  if (notAfter !== null) rows.push(row(w('managed.cert.expires'), [timeView(notAfter, 's'), expired ? [' ', badge('bad', w('managed.cert.expired'))] : null]));
  if (rows.length === 0 && unread === null) return null;
  return el(
    'div',
    { class: 'tc-stack' },
    rows.length === 0 ? null : kv(...rows),
    unread === null ? null : el('p', { class: 'tc-small' }, unread),
    el('p', { class: 'tc-muted tc-small' }, w('edit.site.cert_store')),
  );
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
    /** The site whose panel is drawn, what shows the chosen files of its certificate, and what shows that certificate in the managed store. */
    this.panelOf = null;
    this.filesShown = null;
    this.certificateShown = null;
    this.addButton = button('small', w('edit.sites.add'), () => this.addSite());
    this.table = new Table({
      caption: w('edit.sites.caption'),
      rowKey: (site) => String(site.cid),
      empty: { title: w('edit.sites.empty') },
      columns: [
        { key: 'name', label: w('edit.col.name'), value: (site) => site.name.trim(), mono: true, cell: (site) => nameOf(site) },
        { key: 'hosts', label: w('edit.col.hosts'), value: (site) => linesOf(site.hosts).map((entry) => entry.text).join(' '), mono: true, long: true, cell: (site) => hostsCell(site) },
        { key: 'certificate', label: w('edit.col.certificate'), value: (site) => site.kind, filter: false, cell: (site) => (site.kind === 'acme' ? w('edit.site.kind_acme') : w('edit.site.kind_file')) },
        { key: 'expires', label: timeLabel(w('managed.cert.expires')), value: (site) => this.listed(site)?.notAfter ?? null, text: (site) => expiresText(this.listed(site)), tight: true, cell: (site) => expiresCell(this.listed(site)) },
        { key: 'marks', label: w('col.state'), value: (site) => this.marksOf(site).map((name) => MARKS[name].text()).join(' '), cell: (site) => this.marksCell(site) },
        { key: 'actions', label: w('col.actions'), value: () => '', sortable: false, filter: false, cell: (site) => button('small', w('edit.upstreams.edit'), () => this.openSite(site.cid)) },
      ],
    });
    mount(this.form, panelWith(w('edit.sites.list_title'), [this.addButton], this.sitesNote, this.table.node).node, this.panelBox);
  }

  /** What the managed store holds of the certificates of the selected version and of the version that the draft carries; a read of those that fails fails nothing. */
  async readMore(state) {
    const source = heldDraft()?.sourceName ?? null;
    const [selected, carried] = await Promise.all([this.certificatesOf(state.current), source === state.current ? null : this.certificatesOf(source)]);
    return { certificates: certificateIndex([selected, carried]) };
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
    const key = JSON.stringify(draft.sites.map((site) => [site.cid, site.name, site.hosts, site.kind, this.marksOf(site), this.listed(site)]));
    if (key !== this.listKey) {
      this.listKey = key;
      this.table.update({ rows: draft.sites, loading: false });
    }
    // What the panel shows of its certificate follows the draft and the last read, as the list does.
    const open = this.panelOf === null ? null : draft.site(this.panelOf);
    if (open !== null) this.showCertificate(open);
  }

  // ---- the list ----

  /** What the list shows of the certificate of `site` in the managed store: its state when the key is the same too, and its expiry; null when nothing matches it. */
  listed(site) {
    const found = certificateOf(site, this.data?.certificates ?? null);
    if (found === null) return null;
    return { state: found.whole ? found.answer.state : null, ...certificateExpiry(found.answer) };
  }

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
    this.certificateShown = null;
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
    const stored = el('div');
    this.certificateShown = { cid: site.cid, node: stored, key: null };
    this.showCertificate(site);
    return el('div', { class: 'tc-stack' }, el('h3', {}, w('edit.site.certificate')), note, el('div', { class: 'tc-fields' }, kind.node), files, acme, stored);
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

  /**
   * Shows what the managed store holds of the certificate that the open site names now, when the panel of `site` is the
   * one shown. It is written again only when that changes: this runs with every character that is typed.
   */
  showCertificate(site) {
    const shown = this.certificateShown;
    if (shown?.cid !== site.cid) return;
    const found = certificateOf(site, this.data?.certificates ?? null);
    const key = JSON.stringify(found === null ? null : [found.whole, found.answer]);
    if (key === shown.key) return;
    shown.key = key;
    mount(shown.node, found === null ? null : certificateView(found));
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
