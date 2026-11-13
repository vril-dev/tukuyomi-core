// The band above the screens that edit the draft of the managed configuration, and the screen that holds it: which
// version the draft started from, whether it holds changes, and the buttons that check it, save it and give it up. A
// check asks the API for what it would refuse, and a refusal is put at the field that it names (see `locate.js`). A
// saving is a check, a confirmation and the change itself; the change is told by the job that it starts (see
// `screen.js`), and the draft is matched with what a read of the state says afterwards (see `settleSent`). Nothing runs
// when the module is loaded.

import { ApiError } from '../../api.js';
import { badge, button, el, mount, notice } from '../../dom.js';
import { lazy, t, w } from '../../i18n.js';
import { confirmChange, diffView, fingerprintView, hashOf, isFingerprint, panelWith, setBusy, shortOf, working } from '../../parts.js';
import { Screen, countsOf, diffRows, unusedNotice } from '../screen.js';
import { changesBetween, sitesToIssue } from './changes.js';
import { forgetDraft, heldDraft, readableVersion, savingRuns, settleSaving, syncDraft, watchDraft } from './draft.js';
import { barFault, faultAt } from './locate.js';

/** The largest request of a check or a saving that the admin process reads, and the most files that it takes. */
export const BODY_MAX = 12 << 20;
export const FILES_MAX = 192;

/** The lines that a confirmation shows of what changes; the rest are counted. */
const CHANGES_SHOWN = 20;

const AREAS = {
  upstream: () => w('edit.area.upstream'),
  default: () => w('edit.area.default'),
  access: () => w('edit.area.access'),
  rate_limit: () => w('edit.area.rate_limit'),
  site: () => w('edit.area.site'),
  route: () => w('edit.area.route'),
};
const ACTIONS = {
  add: () => w('edit.change.add'),
  remove: () => w('edit.change.remove'),
  change: () => w('edit.change.change'),
};
// The way to the screen of a field that is told in the band of another screen.
const WAYS = {
  sites: () => w('edit.way.sites'),
  upstreams: () => w('edit.way.upstreams'),
  routes: () => w('edit.way.routes'),
  policy: () => w('edit.way.policy'),
};
// What an answer with nothing in it says, by its status: the proxy in front gave it, not the admin process.
const NO_SENTENCE = {
  413: () => w('edit.proxy.too_large'),
  403: () => w('edit.proxy.refused'),
};

/**
 * What `body` comes to against the limits, with `maxBody` the limit of the body of the proxy in front (when it is
 * known): `tooLarge` and `tooMany` keep it from being sent, and `overProxy` is told and does not, for the proxy may not
 * be in the way.
 */
export function bodySize(body, maxBody) {
  const bytes = new TextEncoder().encode(JSON.stringify(body)).length;
  return { bytes, tooLarge: bytes > BODY_MAX, tooMany: body.files.length > FILES_MAX, overProxy: typeof maxBody === 'number' && bytes > maxBody };
}

/** The words of a refused request, including one that the proxy in front refused with no sentence. */
function refusalWords(error, describe, change) {
  if (error instanceof ApiError && error.sentence === '' && Object.hasOwn(NO_SENTENCE, error.status)) {
    const words = NO_SENTENCE[error.status]();
    return lazy(() => (error.request === '' ? words.text() : `${words} ${t('error.request', { id: error.request })}`));
  }
  return describe(error, { change });
}

/** The fault of a refused request: at its field for a 400 that names one, else in the band. `change` is for a request that changes something. */
export function refusalFault(error, map, describe, change = false) {
  const words = refusalWords(error, describe, change);
  if (error instanceof ApiError && error.status === 400) return faultAt(error.body?.at ?? null, map, words);
  return barFault(words);
}

/**
 * What the answer of a check comes to, for a draft that may have changed since it was asked (`asked` is `{ revision,
 * map }`): `stale`, `same` (no change from the base), `passed` with `to`, or `refused` with its fault. An answer about
 * an older revision is not put on any field.
 */
export function checkFinding(draft, asked, { answer, error }, describe) {
  if (draft.revision !== asked.revision) return { kind: 'stale' };
  if (error !== null) return { kind: 'refused', fault: refusalFault(error, asked.map, describe) };
  if (!isFingerprint(answer.version)) return { kind: 'refused', fault: barFault(w('error.generic')) };
  return answer.version === draft.base ? { kind: 'same' } : { kind: 'passed', to: answer.version };
}

/** The lines of what a change does (see `changesBetween`): the first ones, and how many more there are. */
function changesView(changes) {
  const shown = changes.slice(0, CHANGES_SHOWN);
  const more = changes.length - shown.length;
  return el(
    'ul',
    { class: 'tc-files' },
    shown.map((change) => el('li', {}, ACTIONS[change.action](), ' ', AREAS[change.area](), change.label === '' ? null : [' ', el('code', {}, change.label)])),
    more > 0 ? el('li', { class: 'tc-muted tc-small' }, w('edit.change.more', { n: more })) : null,
  );
}

/**
 * A screen that edits the draft. `screen` is the name of the screen, by which a fault says where it belongs. The form of
 * a screen is made once for each draft, so that a drawing of the band keeps what is typed and the focus; `drawForm`
 * makes it, `drawList` draws what follows the draft, and `openFault` opens the place of a fault of this screen.
 */
export class EditScreen extends Screen {
  constructor(ctx, root, title, intro, screen) {
    super(ctx, root, title, intro);
    this.screen = screen;
    /** The draft that the form was made for. */
    this.formOf = null;
    this.arrived = false;
    this.checkButton = button('', w('edit.check'), () => this.check());
    this.saveButton = button('primary', w('edit.save'), () => this.save());
    this.discardButton = button('danger', w('edit.discard'), () => this.discard());
    this.barState = el('span', { class: 'tc-actions' });
    this.barNotes = el('div', { class: 'tc-stack', 'aria-live': 'polite' });
    this.barBox = panelWith(w('edit.bar.title'), [this.barState], el('p', { class: 'tc-muted tc-small' }, w('edit.bar.memory')), this.barNotes, el('div', { class: 'tc-actions' }, this.checkButton, this.saveButton, this.discardButton)).node;
    /** What the notices of the band and the notice of a base that moved were last drawn from: a notice that is not new is not drawn again, nor read out again. */
    this.toldFaults = null;
    this.toldSaid = null;
    this.toldMoved = null;
    this.notes = el('div', { class: 'tc-stack' });
    /** Everything below the band; it is turned off while this user's saving runs. */
    this.form = el('fieldset', { class: 'tc-edit tc-stack tc-stack--wide' });
    this.barBox.hidden = true;
    this.form.hidden = true;
    /** Where the faults of this screen are shown: `<cid>:<field>` to `{ cid, field, box, note, part }`, a `Field` or a box of notices, and the `details` element around it (or null). */
    this.places = new Map();
    /** The faults that the places show, so that they are written again only when they change. */
    this.faultsShown = null;
    mount(this.body, this.barBox, this.notes, this.form);
    this.unwatchDraft = watchDraft(() => this.onDraft());
  }

  stop() {
    super.stop();
    this.unwatchDraft();
    if (heldDraft() !== null && !heldDraft().changed) forgetDraft();
  }

  onDraft() {
    if (this.alive && this.data !== null) this.drawBody();
  }

  // ---- what a read finds ----

  async read() {
    const { api } = this.ctx;
    const state = await api.call('GET', '/api/managed');
    if (state.managed === false) return { state };
    if (state.managed !== true) throw new Error('not an answer of the managed state');
    const [version, around, more] = await Promise.all([this.readVersion(state.current), this.readAround(), this.readMore(state)]);
    return { state, version, ...around, ...more };
  }

  /** What this screen reads besides, with the others, for the answer `state` of `GET /api/managed`: an object whose keys join what the read found. */
  readMore() {
    return {};
  }

  /** The content of the version `name`, or null when no version is selected. A version that is not in the form of one is a failure of the read. */
  async readVersion(name) {
    if (!isFingerprint(name)) return null;
    const answer = await this.ctx.api.call('GET', `/api/managed/versions/${name}`);
    if (!readableVersion(answer.version)) throw new Error('not a version');
    return answer.version;
  }

  /** A read has been taken in, and the job it found is shown. */
  follow(job) {
    super.follow(job);
    this.settle();
  }

  /** Matches the change that was sent with what the read found, and then the draft with the version that is selected. */
  settle() {
    const { state, version } = this.data;
    if (state.managed !== true) return;
    const saving = settleSaving(state, this.ctx.user.name, working.name);
    if (saving === 'waits') return;
    if (saving === 'unseen') mount(this.results, notice('ok', w('edit.applied_found')));
    if (isFingerprint(state.current) && version !== null) syncDraft(state.current, version, () => this.ctx.api.call('GET', '/api/session'));
  }

  afterLoad() {
    super.afterLoad();
    if (!this.arrived && heldDraft() !== null) {
      this.arrived = true;
      this.openFirstFault(heldDraft());
    }
  }

  // ---- what is shown ----

  /** Whether this user's saving runs: its request has no answer yet, or its job runs and is watched. */
  locked() {
    return savingRuns({ workingName: working.name, watching: this.watch.active, job: this.job, user: this.ctx.user.name });
  }

  mayCheck(draft) {
    return !this.locked() && !draft.checking && draft.reading === 0;
  }

  maySave(draft) {
    return !this.busy() && !draft.checking && draft.reading === 0 && draft.changed && draft.base === this.data?.state?.current;
  }

  /** Whether the draft holds changes and the version that it started from is no longer selected. */
  moved(draft) {
    return draft.changed && isFingerprint(this.data?.state?.current) && draft.base !== this.data.state.current;
  }

  drawBar(draft) {
    setBusy(this.checkButton, !this.mayCheck(draft));
    setBusy(this.saveButton, !this.maySave(draft));
    setBusy(this.discardButton, this.locked());
    mount(this.barState, w('edit.bar.base'), ' ', fingerprintView(draft.base, { copy: false }), ' ', badge(draft.changed ? 'warn' : 'muted', draft.changed ? w('edit.bar.changed') : w('edit.bar.unchanged')));
    this.form.disabled = this.locked();
    if (this.toldFaults === draft.faults && this.toldSaid === draft.said) return;
    this.toldFaults = draft.faults;
    this.toldSaid = draft.said;
    const elsewhere = draft.faults.find((fault) => fault.screen !== null && fault.screen !== this.screen);
    mount(
      this.barNotes,
      draft.said.map((line) => notice(line.tone, line.words)),
      draft.faults.filter((fault) => fault.screen === null).map((fault) => notice('bad', fault.words)),
      elsewhere === undefined ? null : notice('bad', elsewhere.words, ' ', el('a', { class: 'tc-link', href: hashOf(elsewhere.screen) }, WAYS[elsewhere.screen]())),
    );
  }

  /** The panel that says that the base of the draft is no longer selected, with the two ways on. */
  movedNotice() {
    const locked = this.locked();
    return notice(
      'warn',
      w('edit.moved'),
      el(
        'div',
        { class: 'tc-actions' },
        button('small danger', w('edit.moved.discard'), () => this.discard(), { disabled: locked }),
        button('small', w('edit.moved.rebase'), () => this.rebase(), { disabled: locked }),
      ),
    );
  }

  /** What the screen says instead of the band and the form, or null when they are shown. */
  absence() {
    if (this.error !== null) {
      // The draft stays while the state cannot be read, and can be given up meanwhile.
      const draft = heldDraft();
      return [this.failure(w('managed.failed')), draft !== null && draft.changed ? el('div', { class: 'tc-actions' }, button('small danger', w('edit.discard'), () => this.discard(), { disabled: this.locked() })) : null];
    }
    if (this.data === null) return notice('info', w('managed.loading'));
    if (this.data.state.managed !== true) return unusedNotice(this.ctx.user.role);
    if (!isFingerprint(this.data.state.current)) return notice('warn', w('managed.none_selected_hint'));
    return heldDraft() === null ? notice('info', w('managed.loading')) : null;
  }

  /** Draws the state of the draft: everything but the form, which `drawForm` makes once for each draft. */
  drawBody() {
    const absent = this.absence();
    const shown = absent === null;
    // Written only when it changes: this runs with every character that is typed, and a field must keep the focus.
    if (this.barBox.hidden === shown) this.barBox.hidden = !shown;
    if (this.form.hidden === shown) this.form.hidden = !shown;
    if (!shown) {
      this.toldMoved = null;
      mount(this.notes, absent);
      return;
    }
    const draft = heldDraft();
    const moved = `${this.moved(draft)} ${this.locked()}`;
    if (this.toldMoved !== moved) {
      this.toldMoved = moved;
      mount(this.notes, this.moved(draft) ? this.movedNotice() : null);
    }
    this.drawBar(draft);
    if (this.formOf !== draft) {
      this.formOf = draft;
      this.drawForm(draft);
    }
    this.drawList(draft);
    this.showFaults(draft);
  }

  /** Makes the form of this screen for `draft`. */
  drawForm() {}

  /** Draws what of this screen follows the draft. */
  drawList() {}

  // ---- the places of the faults ----

  /** A fault about the field `field` of the item `cid` is told at the `Field` `box`, which is in the `details` element `part` when it is given. */
  placeField(cid, field, box, part = null) {
    this.places.set(`${cid}:${field}`, { cid, field, box, note: null, part });
    this.faultsShown = null;
  }

  /** A fault about the item `cid` that no field holds is told in the box `note`, which is in the `details` element `part` when it is given. */
  placeNote(cid, field, note, part = null) {
    this.places.set(`${cid}:${field}`, { cid, field, box: null, note, part });
    this.faultsShown = null;
  }

  /** Writes at each place what is wrong there now; what the faults of the draft no longer say is taken away. */
  showFaults(draft) {
    if (this.faultsShown === draft.faults) return;
    this.faultsShown = draft.faults;
    for (const place of this.places.values()) {
      const fault = draft.faults.find((one) => one.screen === this.screen && one.cid === place.cid && one.field === place.field);
      // What is wrong is not left in a part that is closed.
      if (fault !== undefined && place.part !== null) place.part.open = true;
      if (place.box === null) mount(place.note, fault === undefined ? null : notice('bad', fault.words));
      else if (fault === undefined) place.box.valid();
      else place.box.invalid(fault.words);
    }
  }

  /** Opens the place of `fault`, which belongs to this screen, and puts the focus on it; a closed `details` around it is opened first, as what is in one cannot take the focus. */
  openFault(fault, draft) {
    this.showFaults(draft);
    const place = this.places.get(`${fault.cid}:${fault.field}`);
    if (place === undefined) return;
    if (place.part !== null) place.part.open = true;
    (place.box === null ? place.note : place.box.control).focus();
  }

  openFirstFault(draft) {
    const fault = draft.firstFault(this.screen);
    if (fault !== null) this.openFault(fault, draft);
  }

  // ---- the check ----

  /** Checks the draft with the API. Gives what the check sent and what it found (`{ body, map, version, to, revision }`), or null when it did not pass. */
  async check() {
    const draft = heldDraft();
    if (draft === null || !this.mayCheck(draft)) return null;
    draft.putFaults([]);
    draft.putSaid([]);
    const built = draft.build();
    if (built.faults !== undefined) {
      draft.putFaults(built.faults);
      this.openFirstFault(draft);
      return null;
    }
    const body = { expect: draft.base, version: built.version, files: built.files };
    const size = bodySize(body, this.data?.file?.maxBody);
    if (size.tooLarge || size.tooMany) {
      draft.putFaults([barFault(size.tooMany ? w('edit.body.too_many') : w('edit.body.too_large'))]);
      return null;
    }
    const overProxy = size.overProxy ? [{ tone: 'warn', words: w('edit.body.over_proxy') }] : [];
    const asked = { revision: draft.revision, map: built.map };
    draft.setChecking(true);
    let outcome;
    try {
      outcome = { answer: await this.ctx.api.call('POST', '/api/managed/check', body), error: null };
    } catch (error) {
      outcome = { answer: null, error };
    }
    draft.setChecking(false);
    if (!this.alive || heldDraft() !== draft) return null;
    const finding = checkFinding(draft, asked, outcome, this.ctx.describe);
    return this.tellFinding(draft, asked, finding, body, built, overProxy);
  }

  /** Tells what a check found; `overProxy` is what the band says of the size of the body, whatever the check found. */
  tellFinding(draft, asked, finding, body, built, overProxy) {
    if (finding.kind === 'stale') {
      draft.putSaid([{ tone: 'warn', words: w('edit.checked.stale') }, ...overProxy]);
      return null;
    }
    if (finding.kind === 'same') {
      draft.putSaid([{ tone: 'info', words: w('edit.checked.same') }, ...overProxy]);
      return null;
    }
    if (finding.kind === 'refused') {
      draft.putFaults([finding.fault]);
      draft.putSaid(overProxy);
      this.openFirstFault(draft);
      return null;
    }
    draft.putSaid([{ tone: 'ok', words: w('edit.checked.passed', { id: shortOf(finding.to) }) }, ...overProxy]);
    return { body, map: asked.map, version: built.version, to: finding.to, revision: asked.revision };
  }

  // ---- the saving ----

  /** Asks whether to save what the check `checked` found, with what changes from the base. */
  askSave(draft, checked) {
    const toIssue = sitesToIssue(draft.baseVersion, checked.version);
    return confirmChange(this.layer, {
      title: w('edit.confirm.title'),
      lines: [
        el('p', {}, w('edit.confirm.what')),
        changesView(changesBetween(draft.baseVersion, checked.version)),
        this.fileWaits() ? notice('warn', w('managed.file_waits')) : null,
        toIssue > 0 ? notice('warn', w('edit.confirm.to_issue', { n: toIssue })) : null,
        draft.choseChain() ? notice('info', w('edit.confirm.expiry')) : null,
        el('p', { class: 'tc-muted tc-small' }, w('managed.confirm.groups_reset')),
      ],
      diff: diffView([w('managed.confirm.now'), w('managed.confirm.after')], diffRows(draft.base, checked.to, countsOf(draft.baseVersion), countsOf(checked.version))),
      confirm: w('edit.save'),
    });
  }

  async save() {
    const draft = heldDraft();
    if (draft === null || !this.maySave(draft)) return;
    const checked = await this.check();
    if (checked === null || !this.alive || heldDraft() !== draft) return;
    const yes = await this.askSave(draft, checked);
    if (!yes || !this.alive || heldDraft() !== draft) return;
    if (draft.revision !== checked.revision) {
      draft.putSaid([{ tone: 'warn', words: w('edit.checked.stale') }]);
      return;
    }
    const prior = this.job === null ? null : { kind: this.job.kind, actor: this.job.actor, to: this.job.to, started: this.job.started };
    await this.send(
      'managed-apply',
      '/api/managed/apply',
      checked.body,
      (outcome) => this.heard(draft, checked, outcome),
      () => this.noteSending(draft, checked, prior),
    );
  }

  /** The saving leaves now. A read that began before it knows nothing of it and would end it, so that read no longer counts. */
  noteSending(draft, checked, prior) {
    this.reads += 1;
    this.loading = false;
    draft.sent = { to: checked.to, revision: draft.revision, prior };
  }

  /** The answer of the saving, whatever screen is shown now: a refusal goes on the draft, for the next band that is shown, and the change is over. */
  heard(draft, checked, { error }) {
    if (error === null || (error instanceof ApiError && error.kind === 'unknown')) return;
    draft.sent = null;
    draft.putFaults([refusalFault(error, checked.map, this.ctx.describe, true)]);
    if (this.alive) this.openFirstFault(draft);
  }

  // ---- giving the draft up, and a new base ----

  async discard() {
    const draft = heldDraft();
    if (draft === null || this.locked()) return;
    if (draft.changed) {
      const yes = await confirmChange(this.layer, { title: w('edit.discard'), lines: [el('p', {}, w('edit.discard.what'))], confirm: w('edit.discard'), tone: 'danger' });
      if (!yes || !this.alive || heldDraft() !== draft) return;
    }
    await this.discardAndRead();
  }

  async discardAndRead() {
    if (this.locked()) return;
    forgetDraft();
    await this.load();
  }

  /** The base of the draft is no longer selected: asks whether to go on from the version that is, and what that undoes. */
  async rebase() {
    const draft = heldDraft();
    if (this.asking || draft === null || this.locked()) return;
    this.asking = true;
    let current;
    let version;
    try {
      const state = await this.ctx.api.call('GET', '/api/managed');
      current = state.current;
      version = await this.readVersion(current);
    } catch (error) {
      if (this.alive) mount(this.results, notice('bad', this.ctx.describe(error)));
      return;
    } finally {
      this.asking = false;
    }
    if (!this.alive || heldDraft() !== draft || !isFingerprint(current) || version === null) return;
    const yes = await confirmChange(this.layer, {
      title: w('edit.moved.rebase'),
      lines: [el('p', {}, w('edit.rebase.what')), changesView(changesBetween(draft.baseVersion, version)), el('p', {}, w('edit.rebase.warn'))],
      confirm: w('edit.moved.rebase'),
    });
    if (!yes || !this.alive || heldDraft() !== draft) return;
    draft.rebase(current, version);
    await this.load();
  }
}
