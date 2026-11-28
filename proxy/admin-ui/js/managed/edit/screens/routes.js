// The screen of the routes: the list of the routes, and one panel below the list that edits the route that is open (the
// host, the path or a regular expression for it, the priority and the group, and the access control, the long responses
// and the rewrite in parts that fold). What is typed goes to the draft, and nothing is saved here: the band above the
// form checks and saves it. The form of a route is made the first time its panel opens, and opening it is no edit. Up to
// 1024 routes are read, so the list is drawn again only when a route changes in a way that it shows. Nothing runs when
// the module is loaded.

import { badge, button, el, mount, setText } from '../../../dom.js';
import { lazy, t, w } from '../../../i18n.js';
import { bytesText, checkbox, choice, panelWith } from '../../../parts.js';
import { Table } from '../../../table.js';
import { mountScreen } from '../../screen.js';
import { EditScreen } from '../bar.js';
import { linesBox, numberBox, selectBox, textBox } from '../form.js';
import { builtRoute, routeTags } from '../route-items.js';
import { rewriteLists } from './rewrite.js';

/** The marks of a route in the list: the tone of the badge, its words and the same words as text. */
const MARKS = {
  fresh: { tone: 'info', words: () => w('edit.mark.new'), text: () => t('edit.mark.new') },
  changed: { tone: 'warn', words: () => w('edit.mark.changed'), text: () => t('edit.mark.changed') },
  fault: { tone: 'bad', words: () => w('edit.mark.fault'), text: () => t('edit.mark.fault') },
};

// The words of what a route has besides its host, its path and its group.
const TAGS = {
  access: () => w('edit.tag.access'),
  rewrite: () => w('edit.tag.rewrite'),
  stream: () => w('edit.tag.stream'),
  max_body: () => w('edit.tag.max_body'),
  records: () => w('edit.tag.records'),
};

const RECORDS = ['best_effort', 'required', 'security'];

/** What a route matches the path with, as the version writes it: its regular expression, or its path. */
const pathOf = (shape) => shape.path_regex ?? shape.path;

/** Whether a part of a rewrite holds a line in any of its lists. */
const holdsText = (item) => Object.entries(item).some(([key, value]) => key !== 'cid' && key !== 'raw' && value !== '');

/** The place that stays when the panel of a route is drawn again. */
const OUTSIDE_PANEL = new Set(['routes:notice']);

class RoutesScreen extends EditScreen {
  constructor(ctx, root) {
    super(ctx, root, w('nav.routes'), w('edit.routes.intro'), 'routes');
    /** The draft that the list was drawn from, and what was last drawn: the number of the changes of the list and the faults. */
    this.shown = null;
    this.listSeen = null;
    this.faultsSeen = null;
    /** What the version would hold for each route, worked out once for each drawing of the list. */
    this.shapes = new Map();
    /** A route was just added: the list goes to the last page when it is drawn with it. */
    this.landLast = false;
    this.routesNote = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.panelBox = el('div');
    /** The route whose panel is drawn. */
    this.panelOf = null;
    this.addButton = button('small', w('edit.routes.add'), () => this.addRoute());
    this.table = new Table({
      caption: w('edit.routes.caption'),
      rowKey: (route) => String(route.cid),
      empty: { title: w('edit.routes.empty') },
      fold: true,
      columns: [
        { key: 'host', label: w('edit.col.host'), value: (route) => this.shapeOf(route).host ?? '', mono: true, long: true, cell: (route) => this.shapeOf(route).host ?? w('edit.col.any') },
        { key: 'path', label: w('edit.col.path'), value: (route) => pathOf(this.shapeOf(route)) ?? '', text: (route) => this.pathText(route), mono: true, long: true, cell: (route) => this.pathCell(route) },
        { key: 'upstream', label: w('edit.col.upstream'), value: (route) => this.shown.nameOf(route.ref), mono: true, long: true },
        { key: 'tags', label: w('edit.col.tags'), value: (route) => routeTags(this.shapeOf(route)).join(' '), filter: false, cell: (route) => this.tagsCell(route) },
        { key: 'marks', label: w('col.state'), value: (route) => this.marksOf(route).map((name) => MARKS[name].text()).join(' '), filter: false, cell: (route) => this.marksCell(route) },
        { key: 'actions', label: w('col.actions'), value: () => '', sortable: false, filter: false, cell: (route) => button('small', w('edit.upstreams.edit'), () => this.openRoute(route.cid)) },
      ],
    });
    mount(this.form, panelWith(w('edit.routes.list_title'), [this.addButton], this.routesNote, this.table.node).node, this.panelBox);
  }

  drawForm(draft) {
    this.places.clear();
    this.placeNote('routes', 'notice', this.routesNote);
    this.listSeen = null;
    this.drawPanel(draft);
  }

  drawList(draft) {
    this.shown = draft;
    // Only when a line would change: the count of the changes of the list and the faults say so without a look at every route.
    if (draft.routeList === this.listSeen && draft.faults === this.faultsSeen) return;
    this.listSeen = draft.routeList;
    this.faultsSeen = draft.faults;
    this.shapes = new Map();
    this.table.update({ rows: draft.routes, loading: false, ...(this.landLast ? { landOn: 'last' } : {}) });
    this.landLast = false;
  }

  // ---- the list ----

  /** What the version would hold for `route`, as the list shows it. */
  shapeOf(route) {
    let shape = this.shapes.get(route);
    if (shape === undefined) {
      shape = builtRoute(route, this.shown.nameOf(route.ref), []);
      this.shapes.set(route, shape);
    }
    return shape;
  }

  /** The text of the path of a route in the list, which the filter looks in: the path or regular expression, and the words of its marks. */
  pathText(route) {
    const shape = this.shapeOf(route);
    return [pathOf(shape) ?? '', shape.path_regex === undefined ? '' : t('edit.col.regex'), shape.priority === undefined ? '' : t('edit.col.priority', { n: shape.priority })].filter((part) => part !== '').join(' ');
  }

  /** The path of a route in the list, with a mark when it is a regular expression and another for its priority when it has one. */
  pathCell(route) {
    const shape = this.shapeOf(route);
    const path = pathOf(shape) ?? w('edit.col.any');
    const marks = [];
    if (shape.path_regex !== undefined) marks.push(badge('muted', w('edit.col.regex')));
    if (shape.priority !== undefined) marks.push(badge('muted', w('edit.col.priority', { n: shape.priority })));
    return marks.length === 0 ? path : el('span', {}, path, ' ', el('span', { class: 'tc-badges' }, marks));
  }

  tagsCell(route) {
    const tags = routeTags(this.shapeOf(route));
    return tags.length === 0 ? null : el('span', { class: 'tc-badges' }, tags.map((tag) => badge('muted', TAGS[tag]())));
  }

  marksOf(route) {
    const draft = this.shown;
    const names = [];
    if (route.fresh) names.push('fresh');
    else if (draft.routeChanged(route)) names.push('changed');
    if (draft.faults.some((one) => one.panel === route.cid)) names.push('fault');
    return names;
  }

  marksCell(route) {
    const names = this.marksOf(route);
    return names.length === 0 ? null : el('span', { class: 'tc-badges' }, names.map((name) => badge(MARKS[name].tone, MARKS[name].words())));
  }

  addRoute() {
    if (this.shown === null) return;
    // Set first: the addition tells the screen, and the list is drawn with the new route before this goes on.
    this.landLast = true;
    this.openRoute(this.shown.addRoute().cid);
  }

  /** Opens the panel of the route `cid` and puts the focus on its host. */
  openRoute(cid) {
    const draft = this.shown;
    draft.openPanels.routes = cid;
    this.drawPanel(draft);
    this.showFaults(draft);
    this.places.get(`${cid}:host`)?.box.control.focus();
  }

  closePanel(draft) {
    const cid = draft.openPanels.routes;
    draft.openPanels.routes = null;
    this.drawPanel(draft);
    if (!this.table.focusRow(String(cid))) this.root.querySelector('h1')?.focus();
  }

  // ---- the panel of a route ----

  drawPanel(draft) {
    for (const key of [...this.places.keys()]) {
      if (!OUTSIDE_PANEL.has(key)) this.places.delete(key);
    }
    const route = draft.route(draft.openPanels.routes);
    this.panelOf = route === null ? null : route.cid;
    if (route === null) {
      mount(this.panelBox);
      return;
    }
    const form = draft.routeForm(route);
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(route.cid, 'notice', note);
    const remove = () => {
      draft.removeRoute(route.cid);
      this.drawPanel(draft);
      this.root.querySelector('h1')?.focus();
    };
    mount(
      this.panelBox,
      panelWith(
        w('edit.route.title'),
        [button('small quiet', w('edit.group.close'), () => this.closePanel(draft))],
        note,
        this.basicFields(draft, route, form),
        this.accessPart(draft, route, form),
        this.streamPart(draft, route, form),
        this.rewritePart(draft, route, form),
        el('div', { class: 'tc-actions' }, button('small danger', w('edit.route.remove'), remove)),
      ).node,
    );
  }

  /** Opens the panel that holds the fault first: the first fault of the draft has made it the open one. */
  openFault(fault, draft) {
    if (fault.panel !== null && fault.panel !== this.panelOf) this.drawPanel(draft);
    super.openFault(fault, draft);
  }

  /** A line of text of a form, whose fault is told at the field. */
  textField(draft, route, item, key, label, hint, part = null) {
    const box = textBox(label, item[key], { hint, onInput: (value) => draft.writeRoute(route, item, key, value) });
    this.placeField(item.cid, key, box, part);
    return box.node;
  }

  basicFields(draft, route, form) {
    const adminHost = this.data?.file?.adminHost ?? null;
    const hostHint = adminHost === null ? w('edit.route.host_hint') : lazy(() => `${t('edit.route.host_hint')} ${t('edit.admin_host', { host: adminHost })}`);
    const groupLabel = (group) => (group.name.trim() === '' ? w('edit.group.unnamed') : group.name.trim());
    const upstream = selectBox(w('edit.route.upstream'), [{ value: '', label: w('edit.route.no_upstream') }, ...draft.groups.map((group) => ({ value: group.cid, label: groupLabel(group) }))], route.ref.cid ?? '', {
      onChange: (value) => draft.setRouteUpstream(route, value),
    });
    this.placeField(route.cid, 'upstream', upstream);
    const maxBody = numberBox(w('edit.route.max_body'), form.max_body, { required: false, hint: this.maxBodyHint(), onInput: (value) => draft.writeRoute(route, form, 'max_body', value) });
    this.placeField(route.cid, 'max_body', maxBody);
    const records = selectBox(w('edit.route.records'), [{ value: '', label: w('edit.route.records_unset') }, ...RECORDS.map((word) => ({ value: word, label: word }))], form.records, {
      hint: this.recordsHint(),
      onChange: (value) => draft.writeRoute(route, form, 'records', value),
    });
    this.placeField(route.cid, 'records', records);
    // The path is one field: what it says is written as the path, or as a regular expression, as the choice below it says. Its help follows the choice.
    const pathHint = (regex) => (regex ? w('edit.route.path_regex_hint') : w('edit.route.path_hint'));
    const path = textBox(w('edit.route.path'), form.path, { hint: pathHint(form.regex), onInput: (value) => draft.writeRoute(route, form, 'path', value) });
    this.placeField(route.cid, 'path', path);
    const regex = checkbox((checked) => {
      draft.setRouteRegex(route, checked);
      setText(path.hint, pathHint(checked));
    });
    regex.checked = form.regex;
    const priority = numberBox(w('edit.route.priority'), form.priority, { required: false, hint: w('edit.route.priority_hint'), onInput: (value) => draft.writeRoute(route, form, 'priority', value) });
    this.placeField(route.cid, 'priority', priority);
    return el(
      'div',
      { class: 'tc-fields' },
      this.textField(draft, route, form, 'host', w('edit.route.host'), hostHint),
      path.node,
      choice(w('edit.route.path_regex'), regex),
      priority.node,
      upstream.node,
      maxBody.node,
      records.node,
    );
  }

  /** The help of the limit of a body: an empty field and 0 mean different things. The limit of the proxy is named when the file was read. */
  maxBodyHint() {
    const maxBody = this.data?.file?.maxBody;
    return typeof maxBody === 'number' ? w('edit.route.max_body_hint', { limit: bytesText(maxBody) }) : w('edit.route.max_body_hint_unknown');
  }

  /** The help of the records; `required` needs `records` in the file, which is said only when the file was read and has none. */
  recordsHint() {
    if (this.data?.file?.records !== false) return w('edit.route.records_hint');
    return lazy(() => `${t('edit.route.records_hint')} ${t('edit.route.no_records')}`);
  }

  /** A part of the panel that folds, open when it holds a value (a fault opens it when it is told). Its content is added afterwards, as the fields need the element for that. */
  partOf(title, open) {
    const part = el('details', { class: 'tc-details' }, el('summary', {}, title));
    part.open = open;
    return part;
  }

  /** The switch of a part of a route and what it shows and hides. Turned off, what the part holds stays in the draft. */
  partSwitch(draft, route, item, label, box) {
    box.hidden = !item.on;
    const use = checkbox((checked) => {
      draft.writeRoute(route, item, 'on', checked);
      box.hidden = !checked;
      // What is hidden cannot be corrected.
      if (!checked) draft.clearFaultsOf(item.cid);
    });
    use.checked = item.on;
    return choice(label, use);
  }

  accessPart(draft, route, form) {
    const { access } = form;
    const part = this.partOf(w('edit.route.access'), access.on);
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(access.cid, 'notice', note, part);
    // Said only when the file was read and has no country database: a list of countries is refused without one.
    const countryHint = this.data?.file?.geo === false ? w('edit.access.no_geo') : null;
    const list = (key, label, hint) => {
      const box = linesBox(label, access[key], { hint, onInput: (value) => draft.writeRoute(route, access, key, value) });
      this.placeField(access.cid, key, box, part);
      return box.node;
    };
    const lists = el(
      'div',
      { class: 'tc-fields tc-fields--two' },
      list('deny_cidrs', w('edit.access.deny_cidrs'), w('edit.access.networks_hint')),
      list('allow_cidrs', w('edit.access.allow_cidrs'), w('edit.access.networks_hint')),
      list('deny_countries', w('edit.access.deny_countries'), countryHint),
      list('allow_countries', w('edit.access.allow_countries'), countryHint),
    );
    part.append(el('div', { class: 'tc-stack' }, note, this.partSwitch(draft, route, access, w('edit.route.access_use'), lists), lists));
    return part;
  }

  streamPart(draft, route, form) {
    const { stream } = form;
    const part = this.partOf(w('edit.route.stream'), stream.on);
    const note = el('div', { class: 'tc-stack', tabindex: '-1' });
    this.placeNote(stream.cid, 'notice', note, part);
    const number = (key, label) => {
      const box = numberBox(label, stream[key], { hint: w('edit.route.stream_ms_hint'), onInput: (value) => draft.writeRoute(route, stream, key, value) });
      this.placeField(stream.cid, key, box, part);
      return box.node;
    };
    const websocket = checkbox((checked) => draft.writeRoute(route, stream, 'websocket', checked));
    websocket.checked = stream.websocket;
    const fields = el('div', { class: 'tc-fields' }, number('idle_ms', w('edit.route.stream_idle')), number('total_ms', w('edit.route.stream_total')), choice(w('edit.route.websocket'), websocket));
    part.append(el('div', { class: 'tc-stack' }, note, this.partSwitch(draft, route, stream, w('edit.route.stream_use'), fields), fields));
    return part;
  }

  rewritePart(draft, route, form) {
    const held = form.rewrite_host !== '' || form.rewrite_path !== '' || [form.query, form.request_headers, form.response_headers].some(holdsText);
    const part = this.partOf(w('edit.route.rewrite'), held);
    const host = this.textField(draft, route, form, 'rewrite_host', w('edit.route.rewrite_host'), w('edit.route.rewrite_host_hint'), part);
    const path = this.textField(draft, route, form, 'rewrite_path', w('edit.route.rewrite_path'), w('edit.route.rewrite_path_hint'), part);
    part.append(el('div', { class: 'tc-stack' }, el('div', { class: 'tc-fields' }, host, path), rewriteLists(this, draft, route, part)));
    return part;
  }
}

export const screens = [{ id: 'routes', title: w('nav.routes'), least: 'operator', mount: mountScreen(RoutesScreen) }];
