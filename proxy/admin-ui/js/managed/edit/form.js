// The controls of the forms of the draft, as `Field`s of the shared parts: a line of text, a number, a box of lines, a
// choice and a file, each with its value when it is made and a function that hears what the user does. The rows that
// can be added and taken away are drawn by `Rows`. Nothing runs when the module is loaded.

import { el, mount } from '../../dom.js';
import { Field, textInput } from '../../parts.js';

const PLAIN_TEXT = { autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false' };

/** A line of text. */
export function textBox(label, value, { hint = null, required = false, placeholder = null, onInput }) {
  const control = textInput({ ...PLAIN_TEXT, placeholder });
  control.value = value;
  control.addEventListener('input', () => onInput(control.value));
  return new Field(label, control, { hint, required });
}

/** A number, typed as text: what is not a number is told when the draft is checked. `required: false` is for one that may stay empty, whose key is then not written. */
export function numberBox(label, value, { hint = null, required = true, onInput }) {
  const control = textInput({ ...PLAIN_TEXT, inputmode: 'numeric' });
  control.value = value;
  control.addEventListener('input', () => onInput(control.value));
  return new Field(label, control, { hint, required });
}

/** A box of text, one line for each item of a list. */
export function linesBox(label, value, { hint = null, rows = 5, required = false, onInput }) {
  const control = el('textarea', { class: 'tc-input tc-input--lines', rows: String(rows), ...PLAIN_TEXT });
  control.value = value;
  control.addEventListener('input', () => onInput(control.value));
  return new Field(label, control, { hint, required });
}

/** A choice of `options` (`{ value, label }`), with `value` chosen; what is chosen is heard as the `value` of an option. */
export function selectBox(label, options, value, { hint = null, onChange }) {
  const control = el(
    'select',
    { class: 'tc-select' },
    options.map((option) => el('option', { value: String(option.value), selected: String(option.value) === String(value) }, option.label)),
  );
  control.value = String(value);
  control.addEventListener('change', () => onChange(control.value));
  return new Field(label, control, { hint });
}

/** A file to choose: the name of the field, drawn as a button, opens the choice, and `onFile` hears the file that was chosen. */
export function fileBox(label, { hint = null, required = false, onFile }) {
  const input = el('input', { type: 'file', class: 'tc-file' });
  input.addEventListener('change', () => {
    const file = input.files[0];
    // Cleared, so that the same file can be chosen again.
    input.value = '';
    if (file !== undefined) onFile(file);
  });
  return new Field(label, input, { hint, required, asButton: true });
}

/** Rows of a form that can be added to and taken away: `line.node` of each of `lines`, in their order. */
export class Rows {
  constructor() {
    this.lines = [];
    this.node = el('div', { class: 'tc-rows' });
  }

  add(line) {
    this.lines.push(line);
    this.draw();
  }

  remove(line) {
    this.lines.splice(this.lines.indexOf(line), 1);
    this.draw();
  }

  draw() {
    mount(this.node, this.lines.map((line) => line.node));
  }
}
