# jsonedit.py
# JSON Tree Editor
# v0.1-draft

import json
import copy
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox, simpledialog
from tkinter.simpledialog import askstring
from pathlib import Path
import os
import tempfile


# ----------------------------
# globals
# ----------------------------

g = {
    "doc": None,                 # dict or list
    "file_path": None,           # Path or None
    "selected_path": None,        # tuple path
    "selected_kind": None,        # "root"|"object"|"array"|"object-key"|"array-element"|"value"
    "path_to_iid": {},            # tuple->iid
    "iid_to_path": {},            # iid->tuple
    "iid_to_kind": {},            # iid->kind
    "expanded_paths": set(),      # set(tuple)
    "suppress_tree_select": 0,    # recursion guard
    "text_dirty": 0,              # 0/1
    "last_error": "",
    "embedded_editor_config": None  # dict or None
}

g_find_session = {
    "term": None,          # str
    "matches": [],         # list of JSON paths (list-paths)
    "index": -1            # current index into matches
}

widgets = {}

THEME_DARK = {
    "bg": "#1e1e1e",
    "fg": "#d4d4d4",
    "muted": "#808080",
    "accent": "#569cd6",
    "error": "#f44747",

    "text_bg": "#1e1e1e",
    "text_fg": "#d4d4d4",
    "text_insert": "#d4d4d4",
    "text_select_bg": "#264f78",
    "text_select_fg": "#ffffff",

    "tree_bg": "#1e1e1e",
    "tree_fg": "#d4d4d4",
    "tree_select_bg": "#264f78",
    "tree_select_fg": "#ffffff",
}


# ----------------------------
# tiny helpers
# ----------------------------

def is_doc_loaded():
    return g["doc"] is not None

def is_selected():
    return g["selected_path"] is not None

def is_selected_structural():
    # structural == object-key or array-element (as per spec)
    return g["selected_kind"] in ("object-key", "array-element")

def is_selected_object_key():
    return g["selected_kind"] == "object-key"

def pretty(obj, indent=2):
    return json.dumps(obj, indent=indent, ensure_ascii=False, sort_keys=False)

def compact(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

def set_status(msg, flags=""):
    """Route a status message to one of the status bar channels.
    
    Flags:
      "V" — validity / document state
      "E" — explanatory or error message
      "p" — JSON path display

    Exactly one channel flag is expected.
    """
    if not flags:
        raise ValueError("set_status requires a channel flag")

    if flags == "V":
        widgets["status_validity"]["text"] = msg
    elif flags == "E":
        widgets["status_error"]["text"] = msg
    elif flags == "p":
        widgets["status_path"]["text"] = msg
    else:
        raise ValueError("Unknown status flag: %r" % flags)

def path_to_str(p):
    if p is None:
        return ""
    return "[" + ", ".join(repr(x) for x in p) + "]"

def get_at_path(p):
    obj = g["doc"]
    for k in p:
        obj = obj[k]
    return obj

def set_at_path(p, value):
    if p is None or len(p) == 0:
        g["doc"] = value
        return
    obj = g["doc"]
    for k in p[:-1]:
        obj = obj[k]
    obj[p[-1]] = value

def delete_at_path(p):
    obj = g["doc"]
    for k in p[:-1]:
        obj = obj[k]
    last = p[-1]
    if isinstance(obj, dict):
        del obj[last]
    else:
        del obj[last]

def parent_path(p):
    if p is None or len(p) == 0:
        return None
    return p[:-1]

def last_key(p):
    if p is None or len(p) == 0:
        return None
    return p[-1]

def deep_copy(x):
    return copy.deepcopy(x)

def atomic_write_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(path))
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def extract_embedded_editor_config(doc):
    # Returns a dict or None
    
    # Case 1: root is dict
    if isinstance(doc, dict):
        cfg = doc.get("jsonedit")
        if isinstance(cfg, dict):
            return cfg
    
    # Case 2: root is list, check element 0
    if isinstance(doc, list) and doc:
        first = doc[0]
        if isinstance(first, dict):
            cfg = first.get("jsonedit")
            if isinstance(cfg, dict):
                return cfg
    
    return None

def collect_key_paths(node, current_path, target_key, out_paths):
    if isinstance(node, dict):
        for key, value in node.items():
            if key == target_key:
                out_paths.append(current_path + [key])
            collect_key_paths(value, current_path + [key], target_key, out_paths)

    elif isinstance(node, list):
        for i, value in enumerate(node):
            collect_key_paths(value, current_path + [i], target_key, out_paths)


# ----------------------------
# validation
# ----------------------------

def parse_json_text(s):
    try:
        obj = json.loads(s)
        return obj, None
    except json.JSONDecodeError as e:
        msg = f"{e.msg} (line {e.lineno}, col {e.colno})"
        return None, msg


# ----------------------------
# tree construction / refresh
# ----------------------------

def remember_expanded_paths():
    g["expanded_paths"].clear()

    def walk(iid):
        if widgets["tree"].item(iid, "open"):
            p = g["iid_to_path"].get(iid)
            if p is not None:
                g["expanded_paths"].add(p)
        for c in widgets["tree"].get_children(iid):
            walk(c)

    for iid in widgets["tree"].get_children(""):
        walk(iid)

def clear_tree_maps():
    g["path_to_iid"].clear()
    g["iid_to_path"].clear()
    g["iid_to_kind"].clear()

def new_iid():
    # Treeview iids are strings; use a monotonic counter
    c = g.get("_iid_counter", 0) + 1
    g["_iid_counter"] = c
    return f"n{c}"

def label_for(p, kind, obj):
    # show keys/indices and type markers
    if kind == "root":
        if isinstance(obj, dict):
            return "root {}"
        if isinstance(obj, list):
            return "root []"
        return "root"
    k = last_key(p)
    if kind == "object-key":
        if isinstance(obj, dict):
            # obj is the value at p
            t = "{}" if isinstance(obj, dict) else "[]" if isinstance(obj, list) else "leaf"
            return f"{k!r}: {t}"
        return f"{k!r}"
    if kind == "array-element":
        t = "{}" if isinstance(obj, dict) else "[]" if isinstance(obj, list) else "leaf"
        return f"[{k}]: {t}"
    if kind == "object":
        return "{}"
    if kind == "array":
        return "[]"
    return "leaf"

def insert_node(parent_iid, p, kind):
    obj = get_at_path(p) if p is not None else g["doc"]
    iid = new_iid()
    txt = label_for(p, kind, obj)
    widgets["tree"].insert(parent_iid, "end", iid=iid, text=txt)
    g["iid_to_path"][iid] = p
    g["iid_to_kind"][iid] = kind
    g["path_to_iid"][p] = iid
    return iid

def build_tree():
    widgets["tree"].delete(*widgets["tree"].get_children(""))
    clear_tree_maps()

    if not is_doc_loaded():
        return

    root_path = tuple()
    root_iid = insert_node("", root_path, "root")

    def rec(parent_iid, p):
        obj = get_at_path(p)

        if isinstance(obj, dict):
            for k in obj.keys():
                cp = p + (k,)
                kid = insert_node(parent_iid, cp, "object-key")
                rec(kid, cp)
        elif isinstance(obj, list):
            for i in range(len(obj)):
                cp = p + (i,)
                kid = insert_node(parent_iid, cp, "array-element")
                rec(kid, cp)
        else:
            # leaf: show nothing beneath
            pass

    rec(root_iid, root_path)

def restore_expanded_paths():
    for p in list(g["expanded_paths"]):
        iid = g["path_to_iid"].get(p)
        if iid:
            widgets["tree"].item(iid, open=True)

def refresh_tree(flags=""):
    preserve_open = "O" in flags
    reselect_path = "p" in flags
    sel = g["selected_path"]
    if preserve_open:
        remember_expanded_paths()
    build_tree()
    if preserve_open:
        restore_expanded_paths()
    if reselect_path and sel is not None:
        select_path(sel)


# ----------------------------
# selection + text sync
# ----------------------------

def mark_text_dirty(flag):
    g["text_dirty"] = 1 if flag else 0
    widgets["text"].edit_modified(False)

def set_text(s, cursor="start", selection="none"):
    t = widgets["text"]
    t.delete("1.0", "end")
    t.insert("1.0", s)

    if cursor == "start":
        t.mark_set("insert", "1.0")
        t.see("1.0")
    elif cursor == "select-entire-value":
        t.mark_set("insert", "1.0")
        t.tag_remove("sel", "1.0", "end")
        t.tag_add("sel", "1.0", "end-1c")
        t.see("1.0")

    if selection == "none":
        t.tag_remove("sel", "1.0", "end")

    mark_text_dirty(0)

def refresh_text_for_path(p, cursor="start", selection="none"):
    if not is_doc_loaded():
        set_text("", cursor="start", selection="none")
        return
    obj = get_at_path(p) if p is not None else g["doc"]
    set_text(pretty(obj, indent=2), cursor=cursor, selection=selection)

def select_path(p, flags=""):
    # Resolve the JSON path to its corresponding Treeview item ID.
    # If the path is not currently represented in the tree, abort safely.
    iid = g["path_to_iid"].get(p)
    if not iid:
        return

    # Perform a programmatic tree selection while suppressing the
    # normal Treeview selection-change handler to avoid reentrancy
    # and duplicate refresh side effects.
    g["suppress_tree_select"] += 1
    try:
        widgets["tree"].selection_set(iid)
        widgets["tree"].focus(iid)
        widgets["tree"].see(iid)
    finally:
        g["suppress_tree_select"] -= 1

    # Update authoritative editor selection state and reflect the
    # newly selected JSON path in the status bar.
    kind = g["iid_to_kind"].get(iid)
    g["selected_path"] = p
    g["selected_kind"] = kind
    set_status(path_to_str(p), "p")

    # Re-evaluate which menu actions are enabled based on the
    # new selection and document state.
    refresh_menu_enablement()

    # Optionally refresh the text pane to show the selected subtree.
    #
    # Flags:
    #   "T" — refresh text pane from the selected subtree
    #   "S" — select all text after refresh (implies overwrite intent)
    #
    # Cursor positioning is only meaningful when text is refreshed.
    # Absence of "T" means the text pane is left completely untouched.
    if "T" in flags:
        if "S" in flags:
            refresh_text_for_path(
                p,
                cursor="select-entire-value",
                selection="none"
            )
        else:
            refresh_text_for_path(
                p,
                cursor="start",
                selection="none"
            )

def handle_tree_selection_changed(event=None):
    if g["suppress_tree_select"]:
        return
    sel = widgets["tree"].selection()
    if not sel:
        return
    iid = sel[0]
    p = g["iid_to_path"].get(iid)
    kind = g["iid_to_kind"].get(iid)

    # same-node policy: untouched
    if p == g["selected_path"]:
        g["selected_kind"] = kind
        set_status(path_to_str(p), "p")
        refresh_menu_enablement()
        return

    g["selected_path"] = p
    g["selected_kind"] = kind
    set_status(path_to_str(p), "p")
    refresh_menu_enablement()

    # Spec: navigating away loses uncommitted edits.
    # We do not auto-commit; we simply refresh the text.
    refresh_text_for_path(p, cursor="start", selection="none")

def handle_text_modified(event=None):
    # Tk Text sets modified flag; we mirror it.
    if widgets["text"].edit_modified():
        g["text_dirty"] = 1
        set_status("(uncommitted edits)", "V")
    # do not clear edit_modified here; we clear it on explicit set/commit


# ----------------------------
# file i/o
# ----------------------------

def handle_open_file_command():
    p = filedialog.askopenfilename(
        title="Open JSON",
        filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
    )
    if not p:
        return
    open_file(Path(p))


def handle_reload_file_command():
    if not g["file_path"]:
        messagebox.showerror("Reload", "No file loaded previously.")
        return
    open_file(g["file_path"])


def open_file(p: Path):
    is_reloading = (p == g["file_path"])
    try:
        s = p.read_text(encoding="utf-8")
    except Exception as e:
        messagebox.showerror("Open", f"Could not read file:\n{e}")
        return

    obj, err = parse_json_text(s)
    if err:
        messagebox.showerror("Open", f"Invalid JSON:\n{err}")
        return
    if not isinstance(obj, (dict, list)):
        messagebox.showerror("Open", "Root must be an object {} or array [].")
        return

    g["doc"] = obj
    g["embedded_editor_config"] = extract_embedded_editor_config(g["doc"])
    g["file_path"] = p
    g["selected_path"] = tuple()
    g["selected_kind"] = "root"

    set_status("reloaded" if is_reloading else "loaded", "V")
    set_status("", "E")
    set_status(path_to_str(g["selected_path"]), "p")

    refresh_tree()
    select_path(tuple(), "T")
    set_title()


def save_file():
    if not is_doc_loaded():
        return
    if g["file_path"] is None:
        p = filedialog.asksaveasfilename(
            title="Save JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not p:
            return
        g["file_path"] = Path(p)

    try:
        s = pretty(g["doc"], indent=2) + "\n"
        atomic_write_text(g["file_path"], s)
    except Exception as e:
        messagebox.showerror("Save", f"Could not write file:\n{e}")
        return

    set_status("saved", "V")
    set_status("", "E")
    set_title()

def create_from_clipboard():
    try:
        s = widgets["root"].clipboard_get()
    except Exception:
        messagebox.showerror("Clipboard", "Clipboard is empty or unavailable.")
        return

    obj, err = parse_json_text(s)
    if err:
        messagebox.showerror("Clipboard", f"Invalid JSON:\n{err}")
        return
    if not isinstance(obj, (dict, list)):
        messagebox.showerror("Clipboard", "Root must be an object {} or array [].")
        return

    g["doc"] = obj
    g["embedded_editor_config"] = extract_embedded_editor_config(g["doc"])
    g["file_path"] = None
    g["selected_path"] = tuple()
    g["selected_kind"] = "root"
    set_status("created", "V")
    set_status("", "E")
    set_status(path_to_str(g["selected_path"]), "p")
    refresh_tree()
    select_path(tuple(), "T")
    set_title()

def exit_application():
    widgets["root"].destroy()


# ----------------------------
# clipboard ops
# ----------------------------

def write_clipboard(s):
    try:
        import pyperclip
    except ImportError:
        root = widgets["root"]
        root.clipboard_clear()
        root.clipboard_append(s)
    else:
        pyperclip.copy(s)

def copy_entire_document(flags="P"):
    if not is_doc_loaded():
        return
    s = pretty(g["doc"], indent=2) if flags != "C" else compact(g["doc"])
    write_clipboard(s)
    set_status("copied", "V")
    set_status("", "E")

def copy_selected_subtree(flags="P"):
    if not is_doc_loaded() or not is_selected():
        return
    obj = get_at_path(g["selected_path"])
    s = pretty(obj, indent=2) if flags != "C" else compact(obj)
    write_clipboard(s)
    set_status("copied node", "V")
    set_status("", "E")


# ----------------------------
# commit: text -> tree
# ----------------------------

def apply_text_to_tree(event=None):
    if not is_doc_loaded() or not is_selected():
        return "break"

    s = widgets["text"].get("1.0", "end-1c")
    obj, err = parse_json_text(s)
    if err:
        set_status("INVALID", "V")
        set_status(str(err), "E")
        g["last_error"] = err
        return "break"

    # Replace subtree at selected path
    p = g["selected_path"]
    if p == tuple():
        if not isinstance(obj, (dict, list)):
            set_status("INVALID", "V")
            set_status("Root must be {} or [].", "E")
            return "break"
        g["doc"] = obj
    else:
        set_at_path(p, obj)

    set_status("valid", "V")
    set_status("", "E")
    mark_text_dirty(0)

    # Tree refresh: preserve open nodes, reselect updated node
    refresh_tree("Op")
    return "break"


# ----------------------------
# prompts
# ----------------------------

def prompt_new_object_key(title="New JSON Key", message="Enter a name for the new key:"):
    while True:
        k = simpledialog.askstring(title, message, parent=widgets["root"])
        if k is None:
            return None
        k = k.strip()
        if not k:
            messagebox.showerror(title, "Key must be non-empty.")
            continue
        return k

def confirm_delete():
    return messagebox.askyesno("Delete Item", "Delete the selected item?")

def prompt_find_key(previous_term):
    return askstring(
        title="Search for:",
        prompt="",
        initialvalue=previous_term or ""
    )


# ----------------------------
# structural operations
# ----------------------------

def raise_structural_item():
    if not is_doc_loaded() or not is_selected_structural():
        return
    p = g["selected_path"]
    pp = parent_path(p)
    if pp is None:
        return
    parent = get_at_path(pp)

    if isinstance(parent, list):
        i = last_key(p)
        if len(parent) <= 1:
            return
        j = (i - 1) % len(parent)
        parent[i], parent[j] = parent[j], parent[i]
        np = pp + (j,)
        refresh_tree("O")
        select_path(np)
        return

    if isinstance(parent, dict):
        k = last_key(p)
        keys = list(parent.keys())
        if len(keys) <= 1:
            return
        i = keys.index(k)
        j = (i - 1) % len(keys)
        keys[i], keys[j] = keys[j], keys[i]
        new_parent = {}
        for kk in keys:
            new_parent[kk] = parent[kk]
        set_at_path(pp, new_parent)
        refresh_tree("O")
        select_path(p)
        return

def lower_structural_item():
    if not is_doc_loaded() or not is_selected_structural():
        return
    p = g["selected_path"]
    pp = parent_path(p)
    if pp is None:
        return
    parent = get_at_path(pp)

    if isinstance(parent, list):
        i = last_key(p)
        if len(parent) <= 1:
            return
        j = (i + 1) % len(parent)
        parent[i], parent[j] = parent[j], parent[i]
        np = pp + (j,)
        refresh_tree("O")
        select_path(np)
        return

    if isinstance(parent, dict):
        k = last_key(p)
        keys = list(parent.keys())
        if len(keys) <= 1:
            return
        i = keys.index(k)
        j = (i + 1) % len(keys)
        keys[i], keys[j] = keys[j], keys[i]
        new_parent = {}
        for kk in keys:
            new_parent[kk] = parent[kk]
        set_at_path(pp, new_parent)
        refresh_tree("O")
        select_path(p)
        return

def insert_structural_item_after():
    if not is_doc_loaded() or not is_selected_structural():
        return
    p = g["selected_path"]
    pp = parent_path(p)
    parent = get_at_path(pp)

    if isinstance(parent, list):
        i = last_key(p)
        parent.insert(i + 1, None)
        np = pp + (i + 1,)
        refresh_tree("O")
        # new node policy: refresh + select entire value
        select_path(np, "TS")
        widgets["text"].focus_set()
        return

    if isinstance(parent, dict):
        oldk = last_key(p)
        k = prompt_new_object_key()
        if k is None:
            return
        if k in parent:
            messagebox.showerror("New JSON Key", "Key already exists in this object.")
            return

        keys = list(parent.keys())
        i = keys.index(oldk)
        keys.insert(i + 1, k)

        new_parent = {}
        for kk in keys:
            if kk == k:
                new_parent[kk] = None
            else:
                new_parent[kk] = parent[kk]
        set_at_path(pp, new_parent)
        np = pp + (k,)
        refresh_tree("O")
        select_path(np, "TS")
        widgets["text"].focus_set()
        return

def duplicate_structural_item():
    if not is_doc_loaded() or not is_selected_structural():
        return
    p = g["selected_path"]
    pp = parent_path(p)
    parent = get_at_path(pp)

    if isinstance(parent, list):
        i = last_key(p)
        parent.insert(i + 1, deep_copy(parent[i]))
        np = pp + (i + 1,)
        refresh_tree("O")
        select_path(np, "TS")
        widgets["tree"].focus_set()
        return

    if isinstance(parent, dict):
        oldk = last_key(p)
        k = prompt_new_object_key(title="New JSON Key", message="Enter a name for the duplicated key:")
        if k is None:
            return
        if k in parent:
            messagebox.showerror("New JSON Key", "Key already exists in this object.")
            return

        keys = list(parent.keys())
        i = keys.index(oldk)
        keys.insert(i + 1, k)

        new_parent = {}
        for kk in keys:
            if kk == k:
                new_parent[kk] = deep_copy(parent[oldk])
            else:
                new_parent[kk] = parent[kk]
        set_at_path(pp, new_parent)

        np = pp + (k,)
        refresh_tree("O")
        select_path(np, "TS")
        widgets["tree"].focus_set()
        return

def rename_structural_key():
    if not is_doc_loaded() or not is_selected_object_key():
        return
    p = g["selected_path"]
    pp = parent_path(p)
    parent = get_at_path(pp)

    if not isinstance(parent, dict):
        return

    oldk = last_key(p)
    k = prompt_new_object_key(title="Rename Key", message="Enter the new key name:")
    if k is None:
        return
    if k == oldk:
        return
    if k in parent:
        messagebox.showerror("Rename Key", "Key already exists in this object.")
        return

    keys = list(parent.keys())
    i = keys.index(oldk)
    keys[i] = k

    val = parent[oldk]
    new_parent = {}
    for kk in keys:
        if kk == k:
            new_parent[kk] = val
        else:
            new_parent[kk] = parent[kk]
    set_at_path(pp, new_parent)

    np = pp + (k,)
    refresh_tree("O")
    # rename: text untouched
    select_path(np)
    return

def pick_selection_after_delete(pp, removed_key):
    parent = get_at_path(pp)

    if isinstance(parent, list):
        # removed_key was an index; list is already shortened
        n = len(parent)
        if n == 0:
            return pp, "parent"
        # priority: next sibling (same index), else previous (index-1), else parent
        i = removed_key
        if i < n:
            return pp + (i,), "next-sibling"
        if i - 1 >= 0:
            return pp + (i - 1,), "previous-sibling"
        return pp, "parent"

    if isinstance(parent, dict):
        keys = list(parent.keys())
        if not keys:
            return pp, "parent"
        # we can only approximate “next sibling” by old ordering position;
        # removed_key is not present, so we pick the key at the same slot index if possible.
        # For safety: use previous if we can’t infer.
        return pp + (keys[-1],), "previous-sibling"

    return pp, "parent"

def delete_structural_item():
    if not is_doc_loaded() or not is_selected_structural():
        return
    if not confirm_delete():
        return

    p = g["selected_path"]
    pp = parent_path(p)
    if pp is None:
        return

    removed = last_key(p)

    # execute delete
    delete_at_path(p)

    # decide new selection
    np, classification = pick_selection_after_delete(pp, removed)

    # refresh tree
    refresh_tree("O")

    # delete note: avoid losing uncommitted edits if text_dirty
    if g["text_dirty"]:
        select_path(np)
        set_status("(uncommitted edits)", "V")
        set_status("Selection changed; text not refreshed (uncommitted edits).", "E")
        return

    # otherwise follow "different-existing-node": refresh, cursor start, selection none
    select_path(np, "T")


# ----------------------------
# help
# ----------------------------

def display_help():
    s = "\n".join([
        "JSON Tree Editor lets you explore and safely edit JSON documents using a tree view and a text editor side by side.",
        "",
        "BASIC WORKFLOW",
        "",
        "1. Load JSON into the program:",
        "   • Use File | Open to load a JSON file, or",
        "   • Use File | Create from Clipboard to paste JSON from the clipboard.",
        "",
        "2. Navigate the JSON structure:",
        "   • Click nodes in the tree on the left to select a portion of the JSON.",
        "   • The selected subtree will appear as editable text on the right.",
        "",
        "3. Edit JSON text:",
        "   • Modify the text in the editor pane on the right.",
        "   • You may freely edit, reformat, or replace the JSON subtree.",
        "",
        "4. Commit your changes:",
        "   • Press Ctrl+Enter, or",
        "   • Click the 'Update Tree' button.",
        "   • The tree view will refresh to reflect your changes.",
        "",
        "5. Export JSON:",
        "   • Use 'Copy Tree' to copy the entire document (pretty-printed).",
        "   • Use 'Copy Tree (compressed)' to copy compact JSON.",
        "   • Use 'Copy Node' to copy only the selected subtree.",
        "   • Use File | Save to write the document to disk.",
        "",
        "IMPORTANT WARNING",
        "",
        "Edits made in the text pane are NOT automatically committed.",
        "Your changes are only applied when you explicitly commit them",
        "using Ctrl+Enter or the 'Update Tree' button.",
        "",
        "If you navigate away from a node without committing,",
        "your edits will be lost.",
    ])

    w = tk.Toplevel(widgets["root"])
    w.title("JSON Tree Editor — Help")
    w.geometry("720x520")
    t = tk.Text(w, wrap="word")
    t.insert("1.0", s)
    t.config(state="disabled")
    t.grid(row=0, column=0, sticky="nsew")
    sb = tk.Scrollbar(w, command=t.yview)
    sb.grid(row=0, column=1, sticky="ns")
    t.config(yscrollcommand=sb.set)
    w.grid_rowconfigure(0, weight=1)
    w.grid_columnconfigure(0, weight=1)


# ----------------------------
# menu enablement
# ----------------------------

def refresh_menu_enablement():
    # menu items in tkinter are by index; we keep references in widgets dict
    if "edit_menu" not in widgets:
        return

    edit_menu = widgets["edit_menu"]

    # Edit menu indices (updated):
    # 0 Search
    # 1 Repeat Search
    # 2 separator
    # 3 Raise
    # 4 Rename
    # 5 Delete
    # 6 Duplicate
    # 7 Insert
    # 8 Lower

    can_struct = is_doc_loaded() and is_selected_structural()
    can_rename = is_doc_loaded() and is_selected_object_key()

    edit_menu.entryconfig(3, state=("normal" if can_struct else "disabled"))  # Raise
    edit_menu.entryconfig(4, state=("normal" if can_rename else "disabled")) # Rename
    edit_menu.entryconfig(5, state=("normal" if can_struct else "disabled"))  # Delete
    edit_menu.entryconfig(6, state=("normal" if can_struct else "disabled"))  # Duplicate
    edit_menu.entryconfig(7, state=("normal" if can_struct else "disabled"))  # Insert
    edit_menu.entryconfig(8, state=("normal" if can_struct else "disabled"))  # Lower


def set_title():
    base = "JSON Tree Editor"
    
    cfg = g.get("embedded_editor_config") or {}
    suffix = cfg.get("window-title")
    
    if isinstance(suffix, str) and suffix.strip():
        title = f"{base}: {suffix.strip()}"
    elif g["file_path"]:
        title = f"{base} — {g['file_path'].name}"
    else:
        title = base
    
    widgets["root"].title(title)


# ----------------------------
# finding
# ----------------------------

def action_find_key():
    previous_term = g_find_session["term"]

    term = prompt_find_key(previous_term)
    if term is None:
        return  # cancel → no-op

    if term == "" or term == previous_term:
        advance_find_session()
        return

    # New term → new session
    matches = []
    collect_key_paths(g["doc"], [], term, matches)

    if not matches:
        clear_find_session()
        set_status(f"Find \"{term}\": no matches", "E")
        return

    g_find_session.update({
        "term": term,
        "matches": [tuple(p) for p in matches],
        "index": 0
    })

    navigate_to_match(0)
    set_status(f'Find "{term}": 1 of {len(matches)}', "E")

def action_repeat_find_key():
    if not g_find_session["matches"]:
        set_status("No active search", "E")
        return

    advance_find_session()

def advance_find_session():
    matches = g_find_session["matches"]
    term = g_find_session["term"]

    if not matches:
        set_status("No active search", "E")
        return

    g_find_session["index"] += 1
    wrapped = False

    if g_find_session["index"] >= len(matches):
        g_find_session["index"] = 0
        wrapped = True

    i = g_find_session["index"]
    navigate_to_match(i)

    if wrapped:
        set_status(f'Find "{term}": wrapped (1 of {len(matches)})', "E")
    else:
        set_status(f'Find "{term}": {i+1} of {len(matches)}', "E")

def clear_find_session():
    g_find_session["term"] = ""
    g_find_session["matches"] = []
    g_find_session["index"] = 0

def navigate_to_match(i):
    select_path(g_find_session["matches"][i], "T")


# ----------------------------
# ui construction
# ----------------------------

def setup_gui():
    root = widgets["root"]

    root.option_add("*tearOff", 0)

    # main grid: editor row (weight 1), action row (0), status row (0)
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    # ---- menubar
    menubar = tk.Menu(root)
    widgets["menubar"] = menubar

    file_menu = tk.Menu(menubar)
    widgets["file_menu"] = file_menu
    file_menu.add_command(label="Open", underline=0, accelerator="Ctrl+O", command=handle_open_file_command)
    file_menu.add_command(label="Reload", underline=0, accelerator="Ctrl+!", command=handle_reload_file_command)
    file_menu.add_command(label="Save", underline=0, accelerator="Ctrl+S", command=save_file)
    file_menu.add_separator()
    file_menu.add_command(label="Create from Clipboard", accelerator="Ctrl+N", underline=12, command=create_from_clipboard)
    file_menu.add_separator()
    file_menu.add_command(label="Exit", accelerator="Ctrl+Q", underline=1, command=exit_application)
    menubar.add_cascade(label="File", underline=0, menu=file_menu)

    edit_menu = tk.Menu(menubar)
    widgets["edit_menu"] = edit_menu
    edit_menu.add_command(label="Search…", accelerator="Ctrl+F", underline=0, command=action_find_key)
    edit_menu.add_command(label="Repeat Search", accelerator="Shift+Ctrl+F", command=action_repeat_find_key)
    edit_menu.add_separator()
    edit_menu.add_command(label="Raise Item", accelerator="Ctrl+Up", command=raise_structural_item)
    edit_menu.add_command(label="Rename Key", accelerator="Ctrl+R", command=rename_structural_key)
    edit_menu.add_command(label="Delete Item", accelerator="Del", command=delete_structural_item)
    edit_menu.add_command(label="Duplicate Item", accelerator="Ctrl+D", command=duplicate_structural_item)
    edit_menu.add_command(label="Insert Item After", accelerator="Ctrl+Right", command=insert_structural_item_after)
    edit_menu.add_command(label="Lower Item", accelerator="Ctrl+Down", command=lower_structural_item)
    menubar.add_cascade(label="Edit", underline=0, menu=edit_menu)

    help_menu = tk.Menu(menubar)
    widgets["help_menu"] = help_menu
    help_menu.add_command(label="Help", underline=0, command=display_help)
    menubar.add_cascade(label="Help", underline=0, menu=help_menu)

    root.config(menu=menubar)

    # ---- editor region: horizontal split
    editor = ttk.Frame(root)
    editor.grid(row=0, column=0, sticky="nsew")
    editor.grid_rowconfigure(0, weight=1)
    editor.grid_columnconfigure(0, weight=1)
    editor.grid_columnconfigure(1, weight=1)

    # tree pane
    tree_frame = ttk.Frame(editor)
    tree_frame.grid(row=0, column=0, sticky="nsew")
    tree_frame.grid_rowconfigure(0, weight=1)
    tree_frame.grid_columnconfigure(0, weight=1)

    tree = ttk.Treeview(tree_frame, show="tree")
    widgets["tree"] = tree
    tree.grid(row=0, column=0, sticky="nsew")

    tree_ys = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree_xs = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree_ys.grid(row=0, column=1, sticky="ns")
    tree_xs.grid(row=1, column=0, sticky="ew")
    tree.configure(yscrollcommand=tree_ys.set, xscrollcommand=tree_xs.set)

    # text pane
    text_frame = ttk.Frame(editor)
    text_frame.grid(row=0, column=1, sticky="nsew")
    text_frame.grid_rowconfigure(0, weight=1)
    text_frame.grid_columnconfigure(0, weight=1)

    text = tk.Text(text_frame, wrap="none", undo=False)
    widgets["text"] = text
    text.grid(row=0, column=0, sticky="nsew")
    
    text_ys = tk.Scrollbar(text_frame, orient="vertical", command=text.yview)
    text_xs = tk.Scrollbar(text_frame, orient="horizontal", command=text.xview)
    text_ys.grid(row=0, column=1, sticky="ns")
    text_xs.grid(row=1, column=0, sticky="ew")
    text.configure(yscrollcommand=text_ys.set, xscrollcommand=text_xs.set)

    # ---- action row
    actions = ttk.Frame(root)
    actions.grid(row=1, column=0, sticky="ew", padx=6, pady=6)
    actions.grid_columnconfigure(0, weight=0)

    b1 = ttk.Button(actions, text="Copy Tree", command=lambda: copy_entire_document("P"))
    b2 = ttk.Button(actions, text="Copy Tree (compressed)", command=lambda: copy_entire_document("C"))
    b3 = ttk.Button(actions, text="Copy Node", command=copy_selected_subtree)
    b4 = ttk.Button(actions, text="Copy Node (compressed)", command=lambda: copy_selected_subtree("C"))    
    b5 = ttk.Button(actions, text="Update Tree", command=apply_text_to_tree)
    b6 = ttk.Button(actions, text="Emit", command=lambda: None)
    b6.state(["disabled"])  # placeholder

    b1.grid(row=0, column=0, padx=4)
    b2.grid(row=0, column=1, padx=4)
    b3.grid(row=0, column=2, padx=4)
    b4.grid(row=0, column=3, padx=4)
    b5.grid(row=0, column=4, padx=16)
    b6.grid(row=0, column=5, padx=4)

    # ---- status bar
    status = ttk.Frame(root)
    status.grid(row=2, column=0, sticky="ew", padx=6, pady=(0, 6))
    status.grid_columnconfigure(0, weight=0)
    status.grid_columnconfigure(1, weight=1)
    status.grid_columnconfigure(2, weight=0)

    widgets["status_validity"] = ttk.Label(status, text="(no document)")
    widgets["status_error"] = ttk.Label(status, text="", anchor="w")
    widgets["status_path"] = ttk.Label(status, text="", anchor="e")

    widgets["status_validity"].grid(row=0, column=0, sticky="w")
    widgets["status_error"].grid(row=0, column=1, sticky="ew", padx=12)
    widgets["status_path"].grid(row=0, column=2, sticky="e")

    # ---- bindings
    tree.bind("<<TreeviewSelect>>", handle_tree_selection_changed)

    root.bind_all("<Control-o>", lambda e: handle_open_file_command())
    root.bind_all("<Control-Shift-1>", lambda e: handle_reload_file_command())
    root.bind_all("<Control-s>", lambda e: save_file())
    root.bind_all("<Control-n>", lambda e: create_from_clipboard())
    root.bind_all("<Control-q>", lambda e: exit_application())
    root.bind_all("<Control-h>", lambda e: display_help())
    root.bind_all("<Control-f>", lambda e: action_find_key())
    root.bind_all("<Control-F>", lambda e: action_repeat_find_key())
    
    tree.bind("<Control-Up>", on_ctrl_up)
    tree.bind("<Control-Down>", on_ctrl_down)
    tree.bind("<Control-Right>", on_ctrl_right)
    tree.bind("<Control-d>", on_ctrl_d)
    tree.bind("<Delete>", on_delete)
    tree.bind("<Control-r>", on_ctrl_r)

    # commit controls: Ctrl+Enter when focus is in text
    text.bind("<Control-Return>", apply_text_to_tree)
    text.bind("<<Modified>>", handle_text_modified)

    refresh_menu_enablement()
    set_title()
    apply_dark_mode()


def apply_dark_mode():
    t = widgets["text"]

    t.configure(
        background=THEME_DARK["text_bg"],
        foreground=THEME_DARK["text_fg"],
        insertbackground=THEME_DARK["text_insert"],
        selectbackground=THEME_DARK["text_select_bg"],
        selectforeground=THEME_DARK["text_select_fg"],
    )

    style = ttk.Style()
    style.theme_use("default")  # important: stable baseline
    
    style.configure(
        "Treeview",
        background=THEME_DARK["tree_bg"],
        foreground=THEME_DARK["tree_fg"],
        fieldbackground=THEME_DARK["tree_bg"],
    )
    
    style.map(
        "Treeview",
        background=[("selected", THEME_DARK["tree_select_bg"])],
        foreground=[("selected", THEME_DARK["tree_select_fg"])],
    )

    style.configure(
        "TLabel",
        background=THEME_DARK["bg"],
        foreground=THEME_DARK["fg"],
    )

    widgets["status_error"].configure(foreground=THEME_DARK["error"])



def on_ctrl_up(event):
    raise_structural_item()
    return "break"

def on_ctrl_down(event):
    lower_structural_item()
    return "break"

def on_ctrl_right(event):
    insert_structural_item_after()
    return "break"

def on_ctrl_d(event):
    duplicate_structural_item()
    return "break"

def on_delete(event):
    delete_structural_item()
    return "break"

def on_ctrl_r(event):
    rename_structural_key()
    return "break"


# ----------------------------
# main
# ----------------------------

def main():
    root = tk.Tk()
    widgets["root"] = root
    setup_gui()

    # start empty
    g["doc"] = None
    set_status("(no document)", "V")
    set_status("", "E")
    set_status("", "p")

    root.mainloop()


if __name__ == "__main__":
    main()
