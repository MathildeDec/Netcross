#!/usr/bin/env python3
"""
netcross_gtk4.app -- interface GTK4 pour netcross_core / netcross_report.

Trois pages navigables (Gtk.Stack + Gtk.StackSwitcher) : Configuration,
Travail (journal d'avancement en temps reel), Resultats. L'analyse tourne
dans un thread d'arriere-plan avec GLib.idle_add pour les mises a jour
d'UI (meme pattern que le plugin Redfish de gnome-connection-manager).
Les zones de defilement utilisent des scrollbars classiques toujours
visibles (pas de survol/auto-masquage) pour qu'elles restent decouvrables.

Parite avec les CLIs (cross_capture_analyzer_cli.py / cross_capture_diff_cli.py) :
    - lecture parallele des captures (--parallel)
    - deduction automatique de topologie (points_order=None, equivalent
      a ne pas passer --order)
    - triage (--triage)
    - diagnostics TLS/QUIC (--tls/--quic), mode analyse simple uniquement
    - export CSV du detail par flux (--detail-csv) / des ecarts (--diff-csv)
    - mode comparaison baseline/courant (cross_capture_diff_cli.py),
      avec export PDF et CSV dedies

Au-dela des CLIs -- capture en direct (netcross_core.parse_live /
pcap_parser.iter_live, jusqu'ici orpheline, aucune CLI ne l'exposait) :
    - mode analyse simple uniquement (pas de diff), un thread par point
      de capture, arret propre via un stop_event partage qui termine le
      sous-processus tshark directement (reactif meme sans trafic sur
      l'interface -- cf. pcap_parser.ek_source._terminate_on_event)
    - arret manuel (bouton) ou automatique (duree max optionnelle)
    - TLS/QUIC indisponibles dans ce mode : ces diagnostics relisent les
      fichiers passes a --capture, et une capture live n'en produit pas
"""

import contextlib
import io
import os
import sys
import threading
import time

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gio, GLib, Gtk  # noqa: E402 -- doit suivre gi.require_version()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Les 2 imports suivants doivent rester apres l'ajout ci-dessus : c'est ce qui rend
# netcross_core/netcross_report importables si ce fichier est lance directement
# (python3 src/netcross_gtk4/app.py) sans PYTHONPATH=src prealable.
from netcross_core import (  # noqa: E402
    AddressRedactor,
    analyse,
    build_wireshark_expert_events,
    correlate,
    parse_capture,
    parse_captures_parallel,
    parse_live,
    print_report,
    redact_packets,
    write_detail_csv,
)
from netcross_core.baseline_diff import diff_reports, print_diff_report, write_diff_csv  # noqa: E402


def _visible_scroller(vexpand=True):
    """ScrolledWindow avec scrollbar classique toujours visible (pas d'overlay
    qui disparait au survol) -- pour que le defilement reste decouvrable."""
    scroller = Gtk.ScrolledWindow()
    scroller.set_vexpand(vexpand)
    scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroller.set_overlay_scrolling(False)
    return scroller


class CaptureRow(Gtk.Box):
    """Une ligne = un point de capture (nom + fichier), reordonnable."""

    def __init__(self, path, default_label):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.path = path
        self.set_margin_top(4)
        self.set_margin_bottom(4)
        self.set_margin_start(8)
        self.set_margin_end(8)

        self.label_entry = Gtk.Entry()
        self.label_entry.set_text(default_label)
        self.label_entry.set_width_chars(12)
        self.label_entry.set_tooltip_text("Nom du point de capture (ex: LAN, WAN, DC)")
        self.append(self.label_entry)

        path_label = Gtk.Label(label=os.path.basename(path))
        path_label.set_hexpand(True)
        path_label.set_halign(Gtk.Align.START)
        path_label.set_tooltip_text(path)
        self.append(path_label)

        up_btn = Gtk.Button(icon_name="go-up-symbolic")
        up_btn.set_tooltip_text("Monter (ordre = chemin physique reseau)")
        up_btn.connect("clicked", self._on_up)
        self.append(up_btn)

        down_btn = Gtk.Button(icon_name="go-down-symbolic")
        down_btn.set_tooltip_text("Descendre")
        down_btn.connect("clicked", self._on_down)
        self.append(down_btn)

        remove_btn = Gtk.Button(icon_name="user-trash-symbolic")
        remove_btn.set_tooltip_text("Retirer cette capture")
        remove_btn.connect("clicked", self._on_remove)
        self.append(remove_btn)

    def _on_up(self, _btn):
        row = self.get_parent()
        listbox = row.get_parent()
        idx = row.get_index()
        if idx > 0:
            listbox.remove(row)
            listbox.insert(row, idx - 1)
            listbox.select_row(row)

    def _on_down(self, _btn):
        row = self.get_parent()
        listbox = row.get_parent()
        idx = row.get_index()
        listbox.remove(row)
        listbox.insert(row, idx + 1)
        listbox.select_row(row)

    def _on_remove(self, _btn):
        row = self.get_parent()
        listbox = row.get_parent()
        listbox.remove(row)

    @property
    def label(self):
        return self.label_entry.get_text().strip()


class LiveCaptureRow(Gtk.Box):
    """Une ligne = un point de capture EN DIRECT (nom + interface + filtre
    BPF optionnel), reordonnable -- pendant de CaptureRow pour la source
    live plutot que fichier. Pas de chemin : rien a choisir via un
    selecteur de fichiers, les champs sont editables directement."""

    def __init__(self, default_label, interface="", bpf_filter=""):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.set_margin_top(4)
        self.set_margin_bottom(4)
        self.set_margin_start(8)
        self.set_margin_end(8)

        self.label_entry = Gtk.Entry()
        self.label_entry.set_text(default_label)
        self.label_entry.set_width_chars(12)
        self.label_entry.set_tooltip_text("Nom du point de capture (ex: LAN, WAN, DC)")
        self.append(self.label_entry)

        self.interface_entry = Gtk.Entry()
        self.interface_entry.set_text(interface)
        self.interface_entry.set_width_chars(10)
        self.interface_entry.set_placeholder_text("eth0, wlan0...")
        self.interface_entry.set_tooltip_text(
            "Nom de l'interface reseau a capturer (voir `tshark -D` ou "
            "`ip link` pour lister les interfaces disponibles)"
        )
        self.interface_entry.set_hexpand(True)
        self.append(self.interface_entry)

        self.filter_entry = Gtk.Entry()
        self.filter_entry.set_text(bpf_filter)
        self.filter_entry.set_placeholder_text("filtre BPF optionnel, ex: tcp port 443")
        self.filter_entry.set_hexpand(True)
        self.append(self.filter_entry)

        up_btn = Gtk.Button(icon_name="go-up-symbolic")
        up_btn.set_tooltip_text("Monter (ordre = chemin physique reseau)")
        up_btn.connect("clicked", self._on_up)
        self.append(up_btn)

        down_btn = Gtk.Button(icon_name="go-down-symbolic")
        down_btn.set_tooltip_text("Descendre")
        down_btn.connect("clicked", self._on_down)
        self.append(down_btn)

        remove_btn = Gtk.Button(icon_name="user-trash-symbolic")
        remove_btn.set_tooltip_text("Retirer ce point de capture")
        remove_btn.connect("clicked", self._on_remove)
        self.append(remove_btn)

    def _on_up(self, _btn):
        row = self.get_parent()
        listbox = row.get_parent()
        idx = row.get_index()
        if idx > 0:
            listbox.remove(row)
            listbox.insert(row, idx - 1)
            listbox.select_row(row)

    def _on_down(self, _btn):
        row = self.get_parent()
        listbox = row.get_parent()
        idx = row.get_index()
        listbox.remove(row)
        listbox.insert(row, idx + 1)
        listbox.select_row(row)

    def _on_remove(self, _btn):
        row = self.get_parent()
        listbox = row.get_parent()
        listbox.remove(row)

    @property
    def label(self):
        return self.label_entry.get_text().strip()

    @property
    def interface(self):
        return self.interface_entry.get_text().strip()

    @property
    def bpf_filter(self):
        return self.filter_entry.get_text().strip() or None


class CaptureListPanel(Gtk.Box):
    """Un panneau autonome liste-de-captures + bouton d'ajout. Utilise une
    fois en mode analyse simple, deux fois cote a cote (baseline/courant)
    en mode comparaison -- voir MainWindow._build_config_page."""

    def __init__(self, heading, on_change=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._on_change = on_change

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.append(
            Gtk.Label(
                label=heading,
                halign=Gtk.Align.START,
                css_classes=["heading"],
                hexpand=True,
            )
        )
        add_btn = Gtk.Button(label="Ajouter une capture")
        add_btn.connect("clicked", self._on_add_clicked)
        header.append(add_btn)
        self.append(header)

        frame = Gtk.Frame()
        frame.set_size_request(-1, 160)
        scroller = _visible_scroller()
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        scroller.set_child(self.listbox)
        frame.set_child(scroller)
        self.append(frame)

    def _on_add_clicked(self, _btn):
        dialog = Gtk.FileDialog()
        filt = Gtk.FileFilter()
        filt.add_pattern("*.pcap")
        filt.add_pattern("*.pcapng")
        filt.set_name("Captures Wireshark (*.pcap, *.pcapng)")
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(filt)
        dialog.set_filters(filters)
        dialog.open_multiple(self.get_root(), None, self._on_files_chosen)

    def _on_files_chosen(self, dialog, result):
        try:
            files = dialog.open_multiple_finish(result)
        except GLib.Error:
            return
        for i in range(files.get_n_items()):
            gfile = files.get_item(i)
            self.add_row(gfile.get_path())

    def add_row(self, path, default_label=None):
        """Expose separement du callback du selecteur pour pouvoir etre
        pilote sans dialogue (tests automatises, appel programmatique)."""
        if default_label is None:
            default_label = os.path.splitext(os.path.basename(path))[0].upper()
        row = CaptureRow(path, default_label)
        self.listbox.append(row)
        if self._on_change:
            self._on_change()
        return row

    def rows(self):
        rows = []
        i = 0
        while True:
            row = self.listbox.get_row_at_index(i)
            if row is None:
                break
            rows.append(row.get_child())
            i += 1
        return rows

    def captures(self):
        """Liste de (label, path) dans l'ordre visuel courant -- cet ordre
        sert de topologie physique quand la deduction automatique est
        desactivee (voir MainWindow.auto_topology_check)."""
        return [(row.label or f"POINT{i + 1}", row.path) for i, row in enumerate(self.rows())]


class LiveCaptureListPanel(Gtk.Box):
    """Pendant de CaptureListPanel pour la capture en direct : meme forme
    (en-tete + liste reordonnable dans un cadre defilant), mais "Ajouter"
    insere directement une ligne vide (pas de selecteur de fichiers --
    rien a choisir sur le disque, l'utilisateur remplit interface/filtre
    a la main)."""

    def __init__(self, heading, on_change=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self._on_change = on_change

        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header.append(
            Gtk.Label(
                label=heading,
                halign=Gtk.Align.START,
                css_classes=["heading"],
                hexpand=True,
            )
        )
        add_btn = Gtk.Button(label="Ajouter un point de capture")
        add_btn.connect("clicked", lambda _b: self.add_row())
        header.append(add_btn)
        self.append(header)

        frame = Gtk.Frame()
        frame.set_size_request(-1, 160)
        scroller = _visible_scroller()
        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.SINGLE)
        scroller.set_child(self.listbox)
        frame.set_child(scroller)
        self.append(frame)

    def add_row(self, default_label=None, interface="", bpf_filter=""):
        if default_label is None:
            default_label = f"POINT{len(self.rows()) + 1}"
        row = LiveCaptureRow(default_label, interface, bpf_filter)
        self.listbox.append(row)
        if self._on_change:
            self._on_change()
        return row

    def rows(self):
        rows = []
        i = 0
        while True:
            row = self.listbox.get_row_at_index(i)
            if row is None:
                break
            rows.append(row.get_child())
            i += 1
        return rows

    def captures(self):
        """Liste de (label, interface, bpf_filter) dans l'ordre visuel
        courant -- meme role que CaptureListPanel.captures() pour la
        source live."""
        return [(row.label or f"POINT{i + 1}", row.interface, row.bpf_filter) for i, row in enumerate(self.rows())]


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="Analyse croisee de captures reseau")
        self.set_default_size(1080, 800)
        self.last_report = None
        # etat du dernier run, pour les exports (varie selon le mode) :
        self.last_mode = None  # "single" ou "diff"
        self.last_flows = None  # mode single : pour --detail-csv
        self.last_findings = None  # mode single : Finding, pour le PDF
        self.last_tls_findings = None  # mode single : TlsFinding, pour le PDF
        self.last_quic_findings = None  # mode single : TlsFinding (QUIC), pour le PDF
        # mode single : ExpertEvent de source "tshark", pour le JSON et le PDF
        # (issue #14). None = non calcule, [] = calcule et aucun signal.
        self.last_wireshark_expert_events = None
        self.last_diff_findings = None  # mode diff : DiffFinding
        self.last_baseline_report = None
        self.last_current_report = None
        self.last_diff_tls_findings_baseline = None  # mode diff : TlsFinding (Session 37)
        self.last_diff_tls_findings_current = None
        self.last_diff_quic_findings_baseline = None
        self.last_diff_quic_findings_current = None

        # etat propre a la capture en direct (mode live, voir _begin_live_capture)
        self._live_capturing = False
        self._live_stop_event = None
        self._live_packets = None
        self._live_lock = None
        self._live_threads = None
        self._live_session_id = 0  # incremente a chaque demarrage -- distingue
        # un minuteur de duree max perime (session
        # precedente) d'un minuteur toujours valide

        header = Gtk.HeaderBar()
        self.set_titlebar(header)

        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        switcher = Gtk.StackSwitcher()
        switcher.set_stack(self.stack)
        header.set_title_widget(switcher)

        self.set_child(self.stack)

        self._build_config_page()
        self._build_work_page()
        self._build_results_page()

        self.stack.set_visible_child_name("config")

    # ================= PAGE 1 : CONFIGURATION =================

    def _build_config_page(self):
        outer_scroller = _visible_scroller()
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.set_margin_top(16)
        page.set_margin_bottom(16)
        page.set_margin_start(16)
        page.set_margin_end(16)
        outer_scroller.set_child(page)

        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.diff_check = Gtk.CheckButton(
            label="Mode comparaison (baseline / courant) -- equivalent de cross_capture_diff_cli.py"
        )
        self.diff_check.connect("toggled", self._on_diff_toggled)
        mode_row.append(self.diff_check)
        self.live_check = Gtk.CheckButton(label="Capture en direct (interfaces reseau, au lieu de fichiers)")
        self.live_check.set_tooltip_text(
            "Capture sur une ou plusieurs interfaces jusqu'a l'arret manuel "
            "ou la duree max. Mode analyse simple uniquement (pas de "
            "comparaison), TLS/QUIC indisponibles (necessitent un fichier "
            "a relire)."
        )
        self.live_check.connect("toggled", self._on_live_toggled)
        mode_row.append(self.live_check)
        page.append(mode_row)

        # -- panneau mode analyse simple (fichiers) --
        self.single_panel = CaptureListPanel(
            "Points de capture (ordre = chemin physique reseau)",
            on_change=self._update_run_sensitivity,
        )
        page.append(self.single_panel)

        # -- panneau mode capture en direct (cache par defaut) --
        self.live_panel = LiveCaptureListPanel(
            "Points de capture en direct (ordre = chemin physique reseau)",
            on_change=self._update_run_sensitivity,
        )
        self.live_panel.set_visible(False)
        page.append(self.live_panel)

        self.live_extra_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.live_extra_box.append(
            Gtk.Label(
                label="Duree max (s, 0 = illimitee -- arret manuel):",
                halign=Gtk.Align.START,
            )
        )
        self.live_duration_spin = Gtk.SpinButton.new_with_range(0, 86400, 10)
        self.live_duration_spin.set_value(0)
        self.live_extra_box.append(self.live_duration_spin)
        self.live_extra_box.set_visible(False)
        page.append(self.live_extra_box)

        # -- panneaux mode comparaison (caches par defaut) --
        self.diff_panels_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.baseline_panel = CaptureListPanel("Baseline (avant)", on_change=self._update_run_sensitivity)
        self.current_panel = CaptureListPanel("Courant (apres)", on_change=self._update_run_sensitivity)
        self.diff_panels_box.append(self.baseline_panel)
        self.diff_panels_box.append(self.current_panel)
        self.diff_panels_box.set_hexpand(True)
        self.baseline_panel.set_hexpand(True)
        self.current_panel.set_hexpand(True)
        self.diff_panels_box.set_visible(False)
        page.append(self.diff_panels_box)

        options_label = Gtk.Label(label="Options d'analyse", halign=Gtk.Align.START, css_classes=["heading"])
        options_label.set_margin_top(12)
        page.append(options_label)

        options = Gtk.Grid(column_spacing=12, row_spacing=8)
        page.append(options)

        options.attach(
            Gtk.Label(label="Fenetre temporelle (ms):", halign=Gtk.Align.START),
            0,
            0,
            1,
            1,
        )
        self.bucket_spin = Gtk.SpinButton.new_with_range(10, 60000, 10)
        self.bucket_spin.set_value(1000)
        options.attach(self.bucket_spin, 1, 0, 1, 1)

        options.attach(Gtk.Label(label="Cadence RTP (Hz):", halign=Gtk.Align.START), 2, 0, 1, 1)
        self.rtp_spin = Gtk.SpinButton.new_with_range(8000, 192000, 1000)
        self.rtp_spin.set_value(8000)
        options.attach(self.rtp_spin, 3, 0, 1, 1)

        self.nat_check = Gtk.CheckButton(label="Correlation tolerante au NAT")
        options.attach(self.nat_check, 0, 1, 2, 1)

        self.parallel_check = Gtk.CheckButton(label="Lecture parallele des captures")
        self.parallel_check.set_tooltip_text(
            "Un processus tshark par fichier au lieu d'un flux sequentiel "
            "(--parallel). Le gain depend du nombre de coeurs disponibles."
        )
        options.attach(self.parallel_check, 2, 1, 2, 1)

        self.redact_check = Gtk.CheckButton(label="Anonymiser les adresses IP/MAC (--redact)")
        self.redact_check.set_tooltip_text(
            "Remplace les adresses IP (plages RFC 5737/3849) et MAC (OUI localement "
            "administre) par des pseudonymes coherents avant l'analyse -- pour "
            "partager un rapport sans exposer l'adressage reel. Mutuellement "
            "exclusif avec Diagnostic TLS/QUIC (pipelines independants qui "
            "accedent aux adresses reelles, voir netcross_core.redact)."
        )
        self.redact_check.connect("toggled", self._on_redact_toggled)
        options.attach(self.redact_check, 0, 3, 4, 1)

        self.auto_topology_check = Gtk.CheckButton(
            label="Deduire la topologie automatiquement (ignore l'ordre de la liste)"
        )
        self.auto_topology_check.set_tooltip_text(
            "Equivalent a ne pas passer --order : deduction par delta TTL + "
            "Jaccard, gere les branchements/convergences. Sinon, l'ordre "
            "visuel des lignes ci-dessus est utilise comme chemin physique."
        )
        options.attach(self.auto_topology_check, 0, 2, 4, 1)

        # -- options specifiques a l'analyse simple (masquees en mode diff) --
        self.single_options_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        single_checks = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        self.triage_check = Gtk.CheckButton(label="Triage (classement des segments)")
        triage_topn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        triage_topn_box.append(Gtk.Label(label="Top"))
        self.triage_topn_spin = Gtk.SpinButton.new_with_range(1, 50, 1)
        self.triage_topn_spin.set_value(5)
        self.triage_topn_spin.set_tooltip_text(
            "Nombre de segments affiches par le triage (equivalent --triage-top-n sur la CLI, defaut : 5)"
        )
        triage_topn_box.append(self.triage_topn_spin)
        self.tls_check = Gtk.CheckButton(label="Diagnostic TLS")
        self.tls_check.set_tooltip_text(
            "Relit les memes fichiers avec un pipeline de decodage independant (via tshark)."
        )
        self.quic_check = Gtk.CheckButton(label="Diagnostic QUIC/HTTP3")
        self.quic_check.set_tooltip_text("Necessite cryptography. Relit les memes fichiers.")
        topn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        topn_box.append(Gtk.Label(label="Top-N graphiques"))
        self.topn_spin = Gtk.SpinButton.new_with_range(1, 20, 1)
        self.topn_spin.set_value(5)
        self.topn_spin.set_tooltip_text(
            "Nombre de categories affichees par graphique temporel dans le rapport "
            "PDF (equivalent --topn-charts sur la CLI, defaut : 5). Sans effet sans "
            "export PDF."
        )
        topn_box.append(self.topn_spin)
        single_checks.append(self.triage_check)
        single_checks.append(triage_topn_box)
        single_checks.append(self.tls_check)
        single_checks.append(self.quic_check)
        single_checks.append(topn_box)
        self.single_options_box.append(single_checks)
        page.append(self.single_options_box)

        # -- options specifiques au mode comparaison (masquees par defaut) --
        self.diff_options_box = Gtk.Grid(column_spacing=12, row_spacing=8)
        self.diff_options_box.attach(
            Gtk.Label(label="Seuil pertes (points de %):", halign=Gtk.Align.START),
            0,
            0,
            1,
            1,
        )
        self.loss_threshold_spin = Gtk.SpinButton.new_with_range(0, 100, 0.5)
        self.loss_threshold_spin.set_value(2.0)
        self.diff_options_box.attach(self.loss_threshold_spin, 1, 0, 1, 1)
        self.diff_options_box.attach(Gtk.Label(label="Seuil latence (ms):", halign=Gtk.Align.START), 2, 0, 1, 1)
        self.latency_threshold_spin = Gtk.SpinButton.new_with_range(0, 10000, 0.5)
        self.latency_threshold_spin.set_value(5.0)
        self.diff_options_box.attach(self.latency_threshold_spin, 3, 0, 1, 1)
        self.diff_tls_check = Gtk.CheckButton(label="Diagnostic TLS")
        self.diff_tls_check.set_tooltip_text(
            "Relit les fichiers baseline ET courant avec un pipeline de decodage "
            "independant (via tshark), affiche l'un sous l'autre (pas de vraie diff "
            "semantique possible entre les deux -- voir claude.md Session 8)."
        )
        self.diff_options_box.attach(self.diff_tls_check, 0, 1, 2, 1)
        self.diff_quic_check = Gtk.CheckButton(label="Diagnostic QUIC/HTTP3")
        self.diff_quic_check.set_tooltip_text("Necessite cryptography. Idem TLS, baseline et courant separement.")
        self.diff_options_box.attach(self.diff_quic_check, 2, 1, 2, 1)
        self.diff_options_box.set_visible(False)
        page.append(self.diff_options_box)

        self.run_btn = Gtk.Button(label="Lancer l'analyse")
        self.run_btn.add_css_class("suggested-action")
        self.run_btn.add_css_class("pill")
        self.run_btn.set_halign(Gtk.Align.END)
        self.run_btn.set_margin_top(8)
        self.run_btn.connect("clicked", self.on_run_analysis)
        self.run_btn.set_sensitive(False)
        page.append(self.run_btn)

        self.stack.add_titled(outer_scroller, "config", "Configuration")

    def _on_diff_toggled(self, _btn):
        if self.diff_check.get_active() and self.live_check.get_active():
            self.live_check.set_active(False)  # declenche _on_live_toggled -> resynchronise tout
        self.live_check.set_sensitive(not self.diff_check.get_active())
        self._sync_panel_visibility()
        self._update_run_sensitivity()
        self._update_run_button_label()

    def _on_live_toggled(self, _btn):
        if self.live_check.get_active() and self.diff_check.get_active():
            self.diff_check.set_active(False)  # declenche _on_diff_toggled -> resynchronise tout
        self.diff_check.set_sensitive(not self.live_check.get_active())
        self._sync_panel_visibility()
        self._update_run_sensitivity()
        self._update_run_button_label()

    def _on_redact_toggled(self, _btn):
        """--redact n'est pas disponible avec TLS/QUIC (pipelines independants
        qui accedent aux adresses reelles, voir netcross_core.redact et
        cross_capture_analyzer_cli.py) -- meme contrainte appliquee aux deux
        modes (simple et comparaison), verifiee aussi a l'execution dans
        on_run_analysis (au cas ou l'ordre de coches inverse ait ete utilise)."""
        redact = self.redact_check.get_active()
        for check in (self.tls_check, self.quic_check, self.diff_tls_check, self.diff_quic_check):
            check.set_sensitive(not redact)
            if redact:
                check.set_active(False)

    def _sync_panel_visibility(self):
        """Point unique qui decide, a partir des deux cases a cocher, quels
        panneaux/options sont visibles -- appele apres tout changement de
        mode pour eviter que diff_check et live_check ne divergent."""
        diff_mode = self.diff_check.get_active()
        live_mode = self.live_check.get_active()
        self.single_panel.set_visible(not diff_mode and not live_mode)
        self.live_panel.set_visible(live_mode)
        self.live_extra_box.set_visible(live_mode)
        self.diff_panels_box.set_visible(diff_mode)
        # triage/TLS/QUIC restent pertinents (et visibles) en capture live --
        # seuls TLS/QUIC sont indisponibles dans ce mode, cf. tls_check/quic_check ci-dessous.
        self.single_options_box.set_visible(not diff_mode)
        self.diff_options_box.set_visible(diff_mode)
        self.tls_check.set_sensitive(not live_mode)
        self.quic_check.set_sensitive(not live_mode)
        if live_mode:
            self.tls_check.set_active(False)
            self.quic_check.set_active(False)
        self.parallel_check.set_sensitive(not live_mode)

    def _update_run_button_label(self):
        if self._live_capturing:
            return  # deja gere par _begin_live_capture/_end_live_capture
        self.run_btn.set_label("Demarrer la capture" if self.live_check.get_active() else "Lancer l'analyse")

    def _update_run_sensitivity(self):
        if self._live_capturing:
            return  # bouton deja dans le bon etat pendant une capture en cours
        if self.diff_check.get_active():
            ok = len(self.baseline_panel.rows()) >= 2 and len(self.current_panel.rows()) >= 2
        elif self.live_check.get_active():
            ok = len(self.live_panel.rows()) >= 2
        else:
            ok = len(self.single_panel.rows()) >= 2
        self.run_btn.set_sensitive(ok)

    # ================= compat retro (tests existants) =================
    # Certains appelants (tests) pilotaient directement l'ancienne API a
    # panneau unique : on la fait pointer vers single_panel.

    def add_capture_row(self, path, default_label=None):
        return self.single_panel.add_row(path, default_label)

    # ================= PAGE 2 : TRAVAIL / JOURNAL =================

    def _build_work_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.set_margin_top(16)
        page.set_margin_bottom(16)
        page.set_margin_start(16)
        page.set_margin_end(16)

        page.append(Gtk.Label(label="Avancement", halign=Gtk.Align.START, css_classes=["heading"]))

        progress_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.spinner = Gtk.Spinner()
        progress_row.append(self.spinner)
        self.work_status_label = Gtk.Label(
            label="En attente du lancement de l'analyse...",
            halign=Gtk.Align.START,
            hexpand=True,
        )
        progress_row.append(self.work_status_label)
        self.work_stop_btn = Gtk.Button(label="Arreter et analyser")
        self.work_stop_btn.add_css_class("suggested-action")
        self.work_stop_btn.set_tooltip_text(
            "Termine la capture en direct sur tous les points et lance l'analyse sur les paquets accumules jusqu'ici."
        )
        self.work_stop_btn.set_visible(False)
        self.work_stop_btn.connect("clicked", lambda _b: self._end_live_capture())
        progress_row.append(self.work_stop_btn)
        page.append(progress_row)

        log_frame = Gtk.Frame()
        log_scroller = _visible_scroller()
        self.log_view = Gtk.TextView()
        self.log_view.set_editable(False)
        self.log_view.set_monospace(True)
        self.log_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.log_view.set_top_margin(8)
        self.log_view.set_left_margin(8)
        self.log_view.set_right_margin(8)
        log_scroller.set_child(self.log_view)
        log_frame.set_child(log_scroller)
        log_frame.set_vexpand(True)
        page.append(log_frame)

        self.stack.add_titled(page, "log", "Travail")

    def _log(self, message):
        buf = self.log_view.get_buffer()
        end = buf.get_end_iter()
        buf.insert(end, message + "\n")
        mark = buf.create_mark(None, buf.get_end_iter(), False)
        self.log_view.scroll_to_mark(mark, 0.0, False, 0.0, 1.0)
        return False

    # ================= PAGE 3 : RESULTATS =================

    def _build_results_page(self):
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        page.set_margin_top(16)
        page.set_margin_bottom(16)
        page.set_margin_start(16)
        page.set_margin_end(16)

        page.append(Gtk.Label(label="Resultats", halign=Gtk.Align.START, css_classes=["heading"]))

        result_frame = Gtk.Frame()
        result_scroller = _visible_scroller()
        self.result_view = Gtk.TextView()
        self.result_view.set_editable(False)
        self.result_view.set_monospace(True)
        self.result_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.result_view.set_top_margin(8)
        self.result_view.set_left_margin(8)
        self.result_view.set_right_margin(8)
        result_scroller.set_child(self.result_view)
        result_frame.set_child(result_scroller)
        result_frame.set_vexpand(True)
        page.append(result_frame)

        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.status_label = Gtk.Label(label="", halign=Gtk.Align.START, hexpand=True)
        bottom.append(self.status_label)

        new_btn = Gtk.Button(label="Nouvelle analyse")
        new_btn.connect("clicked", lambda _b: self.stack.set_visible_child_name("config"))
        bottom.append(new_btn)

        self.csv_btn = Gtk.Button(label="Exporter en CSV")
        self.csv_btn.set_sensitive(False)
        self.csv_btn.connect("clicked", self.on_export_csv)
        bottom.append(self.csv_btn)

        self.pdf_btn = Gtk.Button(label="Exporter en PDF")
        self.pdf_btn.add_css_class("suggested-action")
        self.pdf_btn.set_sensitive(False)
        self.pdf_btn.connect("clicked", self.on_export_pdf)
        bottom.append(self.pdf_btn)

        self.json_btn = Gtk.Button(label="Exporter en JSON")
        self.json_btn.set_sensitive(False)
        self.json_btn.connect("clicked", self.on_export_json)
        bottom.append(self.json_btn)
        page.append(bottom)

        self.stack.add_titled(page, "results", "Resultats")

    # ================= lancement de l'analyse =================

    def on_run_analysis(self, _btn):
        if self.live_check.get_active():
            if self._live_capturing:
                self._end_live_capture()
            else:
                self._begin_live_capture()
            return

        diff_mode = self.diff_check.get_active()
        bucket_ms = self.bucket_spin.get_value()
        rtp_rate = int(self.rtp_spin.get_value())
        nat_tolerant = self.nat_check.get_active()
        parallel = self.parallel_check.get_active()
        auto_topology = self.auto_topology_check.get_active()
        redact = self.redact_check.get_active()

        if redact and (
            self.tls_check.get_active()
            or self.quic_check.get_active()
            or self.diff_tls_check.get_active()
            or self.diff_quic_check.get_active()
        ):
            # Filet de securite (voir _on_redact_toggled pour le cas normal,
            # deja empeche via la sensibilite des cases) -- ne devrait pas
            # arriver en pratique, mais mieux vaut refuser explicitement
            # qu'anonymiser partiellement le rapport sans le signaler.
            self.stack.set_visible_child_name("log")
            self._log("--redact n'est pas disponible avec Diagnostic TLS/QUIC (voir netcross_core.redact).")
            return

        self.run_btn.set_sensitive(False)
        self.pdf_btn.set_sensitive(False)
        self.csv_btn.set_sensitive(False)
        self.json_btn.set_sensitive(False)
        self.log_view.get_buffer().set_text("")
        self.work_status_label.set_text("Analyse en cours...")
        self.spinner.start()
        self.stack.set_visible_child_name("log")

        if diff_mode:
            baseline_captures = self.baseline_panel.captures()
            current_captures = self.current_panel.captures()
            loss_min_pp = self.loss_threshold_spin.get_value()
            latency_min_ms = self.latency_threshold_spin.get_value()
            diff_tls = self.diff_tls_check.get_active()
            diff_quic = self.diff_quic_check.get_active()
            threading.Thread(
                target=self._run_diff_thread,
                args=(
                    baseline_captures,
                    current_captures,
                    bucket_ms,
                    rtp_rate,
                    nat_tolerant,
                    parallel,
                    auto_topology,
                    loss_min_pp,
                    latency_min_ms,
                    redact,
                    diff_tls,
                    diff_quic,
                ),
                daemon=True,
            ).start()
        else:
            captures = self.single_panel.captures()
            triage = self.triage_check.get_active()
            triage_topn = int(self.triage_topn_spin.get_value())
            tls = self.tls_check.get_active()
            quic = self.quic_check.get_active()
            topn = int(self.topn_spin.get_value())
            threading.Thread(
                target=self._run_analysis_thread,
                args=(
                    captures,
                    bucket_ms,
                    rtp_rate,
                    nat_tolerant,
                    parallel,
                    auto_topology,
                    triage,
                    triage_topn,
                    tls,
                    quic,
                    redact,
                    topn,
                ),
                daemon=True,
            ).start()

    # ================= capture en direct =================
    # Mode a part : pas de fichiers a lire, un thread par point tourne
    # jusqu'a l'arret (manuel ou duree max), puis les paquets accumules
    # rejoignent exactement le meme pipeline correlate/analyse/rapport
    # que le mode fichier (voir _join_live_and_analyze) -- CSV/PDF/triage
    # marchent donc sans rien y changer.

    def _begin_live_capture(self):
        rows_data = self.live_panel.captures()  # [(label, interface, bpf_filter), ...]
        missing = [label for label, iface, _ in rows_data if not iface]
        if missing:
            self.stack.set_visible_child_name("log")
            self._log(
                f"Interface manquante pour : {', '.join(missing)} -- "
                f"capture annulee (renseignez une interface par point)."
            )
            return

        # snapshot des reglages sur le thread principal (widgets GTK non
        # thread-safe) -- reutilise tel quel par _join_live_and_analyze,
        # qui tourne dans un thread d'arriere-plan et ne doit plus y toucher
        auto_topology = self.auto_topology_check.get_active()
        self._live_bucket_ms = self.bucket_spin.get_value()
        self._live_rtp_rate = int(self.rtp_spin.get_value())
        self._live_nat_tolerant = self.nat_check.get_active()
        self._live_triage = self.triage_check.get_active()
        self._live_triage_topn = int(self.triage_topn_spin.get_value())
        self._live_points_order = None if auto_topology else [label for label, _, _ in rows_data]

        self._live_capturing = True
        self._live_stop_event = threading.Event()
        self._live_packets = []
        self._live_lock = threading.Lock()
        self._live_threads = []

        self.live_panel.set_sensitive(False)
        self.live_extra_box.set_sensitive(False)
        self.run_btn.set_label("Arreter et analyser")
        self.pdf_btn.set_sensitive(False)
        self.csv_btn.set_sensitive(False)
        self.log_view.get_buffer().set_text("")
        self.work_status_label.set_text(
            'Capture en direct en cours -- cliquez sur "Arreter et analyser" quand vous avez assez de trafic capture.'
        )
        self.work_stop_btn.set_visible(True)
        self.spinner.start()
        self.stack.set_visible_child_name("log")

        for label, interface, bpf_filter in rows_data:
            t = threading.Thread(
                target=self._live_capture_worker,
                args=(label, interface, bpf_filter),
                daemon=True,
            )
            self._live_threads.append(t)
            t.start()

        self._live_session_id += 1
        duration = self.live_duration_spin.get_value()
        if duration > 0:
            GLib.timeout_add_seconds(int(duration), self._on_live_duration_elapsed, self._live_session_id)

    def _on_live_duration_elapsed(self, session_id):
        if self._live_capturing and session_id == self._live_session_id:
            self._log("Duree maximale atteinte -- arret automatique de la capture.")
            self._end_live_capture()
        return False  # ne pas repeter le timeout (GLib.timeout_add_seconds)

    def _live_capture_worker(self, label, interface, bpf_filter):
        GLib.idle_add(
            self._log,
            f"[{label}] capture demarree sur {interface}"
            + (f" (filtre BPF: {bpf_filter})" if bpf_filter else "")
            + "...",
        )
        count = 0
        last_log = time.time()
        try:
            for pkt in parse_live(
                label,
                interface,
                bpf_filter=bpf_filter,
                stop_event=self._live_stop_event,
            ):
                with self._live_lock:
                    self._live_packets.append(pkt)
                count += 1
                now = time.time()
                if now - last_log >= 1.0:
                    GLib.idle_add(self._log, f"  [{label}] {count} paquets...")
                    last_log = now
        except Exception as e:  # noqa: BLE001 -- thread de fond : toute erreur
            # (tshark, interface, permission...) doit remonter au journal GUI
            # plutot que de tuer le thread silencieusement.
            GLib.idle_add(self._log, f"[{label}] ERREUR : {e}")
        GLib.idle_add(self._log, f"[{label}] capture arretee -- {count} paquet(s) au total.")

    def _end_live_capture(self):
        if not self._live_capturing or self._live_stop_event.is_set():
            return  # deja arrete/en cours d'arret -- evite un double-clic
            # (bouton config + bouton page Travail) qui lancerait
            # deux threads d'analyse en parallele sur les memes paquets
        self.run_btn.set_sensitive(False)
        self.work_stop_btn.set_sensitive(False)
        self.run_btn.set_label("Arret de la capture...")
        self.work_status_label.set_text("Arret de la capture en cours (peut prendre quelques secondes)...")
        self._live_stop_event.set()
        threading.Thread(target=self._join_live_and_analyze, daemon=True).start()

    def _join_live_and_analyze(self):
        for t in self._live_threads:
            t.join()
        with self._live_lock:
            all_packets = list(self._live_packets)
        GLib.idle_add(
            self._log,
            f"Capture terminee -- {len(all_packets)} paquet(s) au total. Analyse...",
        )
        try:
            GLib.idle_add(self._log, "Correlation des flux entre points de capture...")
            flows = correlate(all_packets, self._live_nat_tolerant, 200)
            GLib.idle_add(self._log, f"  -> {len(flows)} flux identifies")

            GLib.idle_add(
                self._log,
                "Analyse (pertes, latence, TTL, QoS, fragmentation, debit, TCP, VLAN, RTP, DHCP, SIP...)...",
            )
            report = analyse(
                flows,
                self._live_points_order,
                all_packets,
                self._live_bucket_ms / 1000.0,
                self._live_nat_tolerant,
                self._live_rtp_rate,
            )

            GLib.idle_add(self._log, "Mise en forme du rapport...")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_report(report)

            findings = None
            if self._live_triage:
                GLib.idle_add(self._log, "Triage des segments...")
                from netcross_report import (
                    build_findings,
                    format_health_line,
                    health_score,
                    print_triage,
                    rank_segments,
                )

                findings = build_findings(report)
                ranked = rank_segments(findings)
                with contextlib.redirect_stdout(buf):
                    print("\n" + "=" * 70)
                    print("TRIAGE -- PAR OU COMMENCER")
                    print("=" * 70)
                    print_triage(ranked, self._live_triage_topn)
                    print(format_health_line(health_score(ranked)))

            text = buf.getvalue()
        except Exception as e:  # noqa: BLE001 -- thread de fond (analyse live) : toute erreur doit remonter au journal GUI.
            GLib.idle_add(self._log, f"ERREUR : {e}")
            GLib.idle_add(self._on_analysis_error, str(e))
            GLib.idle_add(self._reset_live_ui)
            return
        GLib.idle_add(self._log, "Analyse terminee.")
        GLib.idle_add(
            self._on_analysis_done,
            "single",
            report,
            flows,
            findings,
            text,
            None,
            None,
            build_wireshark_expert_events(all_packets),
        )
        GLib.idle_add(self._reset_live_ui)

    def _reset_live_ui(self):
        self._live_capturing = False
        self.live_panel.set_sensitive(True)
        self.live_extra_box.set_sensitive(True)
        self.work_stop_btn.set_visible(False)
        self.work_stop_btn.set_sensitive(True)
        self._update_run_button_label()
        self._update_run_sensitivity()
        return False

    def _load_packets(self, captures, parallel):
        """Commun aux deux modes : lecture sequentielle ou parallele, avec
        journalisation -- equivalent de _load_packets() des deux CLIs."""
        all_packets = []
        if parallel:
            all_packets, per_file_stats = parse_captures_parallel(captures)
            for s in per_file_stats:
                if s["error"]:
                    GLib.idle_add(
                        self._log,
                        f"  [{s['label']}] ECHEC sur {s['path']} : {s['error']}",
                    )
                else:
                    GLib.idle_add(
                        self._log,
                        f"  [{s['label']}] {s['count']} paquets charges depuis {s['path']} ({s['seconds']:.2f}s)",
                    )
        else:
            for label, path in captures:
                GLib.idle_add(self._log, f"Lecture de {os.path.basename(path)} ({label})...")
                pkts = parse_capture(label, path)
                all_packets.extend(pkts)
                GLib.idle_add(self._log, f"  -> {len(pkts)} paquets charges")
        return all_packets

    def _run_analysis_thread(
        self,
        captures,
        bucket_ms,
        rtp_rate,
        nat_tolerant,
        parallel,
        auto_topology,
        triage,
        triage_topn,
        tls,
        quic,
        redact,
        topn,
    ):
        try:
            points_order = None if auto_topology else [label for label, _ in captures]

            all_packets = self._load_packets(captures, parallel)

            if redact:
                GLib.idle_add(self._log, "Anonymisation des adresses IP/MAC (--redact)...")
                redactor = redact_packets(all_packets)
                GLib.idle_add(self._log, f"  -> {len(redactor)} adresse(s) anonymisee(s)")

            GLib.idle_add(self._log, "Correlation des flux entre points de capture...")
            flows = correlate(all_packets, nat_tolerant, 200)
            GLib.idle_add(self._log, f"  -> {len(flows)} flux identifies")

            GLib.idle_add(
                self._log,
                "Analyse (pertes, latence, TTL, QoS, fragmentation, debit, TCP, VLAN, RTP, DHCP, SIP...)...",
            )
            report = analyse(
                flows,
                points_order,
                all_packets,
                bucket_ms / 1000.0,
                nat_tolerant,
                rtp_rate,
                topn,
            )

            # Signaux d'expertise BRUTS tshark : calcules ici, tant que les
            # paquets sont sous la main. Les exports (JSON/PDF) surviennent
            # apres la fin du thread, quand `all_packets` a ete libere --
            # c'est le calcul qu'on avance, pas les paquets qu'on retient
            # (voir _on_analysis_done).
            GLib.idle_add(self._log, "Expertise tshark (signaux bruts)...")
            wireshark_expert_events = build_wireshark_expert_events(all_packets)
            GLib.idle_add(self._log, f"  -> {len(wireshark_expert_events)} signal(aux) d'expertise")

            GLib.idle_add(self._log, "Mise en forme du rapport...")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_report(report)

            findings = None
            tls_findings = None
            quic_findings = None
            if triage:
                GLib.idle_add(self._log, "Triage des segments...")
                from netcross_report import (
                    build_findings,
                    format_health_line,
                    health_score,
                    print_triage,
                    rank_segments,
                )

                findings = build_findings(report)
                ranked = rank_segments(findings)
                with contextlib.redirect_stdout(buf):
                    print("\n" + "=" * 70)
                    print("TRIAGE -- PAR OU COMMENCER")
                    print("=" * 70)
                    print_triage(ranked, triage_topn)
                    print(format_health_line(health_score(ranked)))

            if tls:
                GLib.idle_add(self._log, "Diagnostic TLS (relecture des captures via tshark)...")
                from netcross_core.tls_diagnostics import (
                    build_handshake_status,
                    diagnose_tls,
                    parse_tls_capture,
                    print_tls_diagnostics,
                )

                tls_events = []
                for label, path in captures:
                    tls_events.extend(parse_tls_capture(label, path))
                status_by_point = build_handshake_status(tls_events)
                tls_findings = diagnose_tls(status_by_point, report.points)
                with contextlib.redirect_stdout(buf):
                    print("\n" + "=" * 70)
                    print("DIAGNOSTIC TLS")
                    print("=" * 70)
                    print_tls_diagnostics(tls_findings)

            if quic:
                GLib.idle_add(self._log, "Diagnostic QUIC (relecture des captures via tshark)...")
                try:
                    from netcross_core.quic_diagnostics import (
                        diagnose_quic,
                        parse_quic_capture,
                        print_quic_diagnostics,
                    )
                except ImportError:
                    with contextlib.redirect_stdout(buf):
                        print("\n--quic necessite cryptography : pip install cryptography --break-system-packages")
                else:
                    quic_events = []
                    for label, path in captures:
                        quic_events.extend(parse_quic_capture(label, path))
                    quic_findings = diagnose_quic(quic_events, report.points)
                    with contextlib.redirect_stdout(buf):
                        print("\n" + "=" * 70)
                        print("DIAGNOSTIC QUIC/HTTP3")
                        print("=" * 70)
                        print_quic_diagnostics(quic_findings)

            text = buf.getvalue()
        except Exception as e:  # noqa: BLE001 -- thread de fond (analyse fichier) : toute erreur doit remonter au journal GUI.
            GLib.idle_add(self._log, f"ERREUR : {e}")
            GLib.idle_add(self._on_analysis_error, str(e))
            return
        GLib.idle_add(self._log, "Analyse terminee.")
        GLib.idle_add(
            self._on_analysis_done,
            "single",
            report,
            flows,
            findings,
            text,
            tls_findings,
            quic_findings,
            wireshark_expert_events,
        )

    def _run_diff_thread(
        self,
        baseline_captures,
        current_captures,
        bucket_ms,
        rtp_rate,
        nat_tolerant,
        parallel,
        auto_topology,
        loss_min_pp,
        latency_min_ms,
        redact,
        tls,
        quic,
    ):
        try:
            redactor = AddressRedactor() if redact else None
            points_order = None if auto_topology else [label for label, _ in baseline_captures]

            GLib.idle_add(self._log, "=== CHARGEMENT DU BASELINE ===")
            baseline_packets = self._load_packets(baseline_captures, parallel)
            if redactor is not None:
                redactor.redact(baseline_packets)
            baseline_flows = correlate(baseline_packets, nat_tolerant, 200)
            baseline_report = analyse(
                baseline_flows,
                points_order,
                baseline_packets,
                bucket_ms / 1000.0,
                nat_tolerant,
                rtp_rate,
            )

            points_order_current = None if auto_topology else [label for label, _ in current_captures]
            GLib.idle_add(self._log, "=== CHARGEMENT DU RUN COURANT ===")
            current_packets = self._load_packets(current_captures, parallel)
            if redactor is not None:
                # meme objet redactor pour baseline ET courant : une adresse
                # reelle presente des deux cotes doit obtenir le meme
                # pseudonyme, sans quoi le diff perdrait tout son sens.
                redactor.redact(current_packets)
                GLib.idle_add(self._log, f"{len(redactor)} adresse(s) anonymisee(s) (IP/MAC) -- baseline et courant.")
            current_flows = correlate(current_packets, nat_tolerant, 200)
            current_report = analyse(
                current_flows,
                points_order_current,
                current_packets,
                bucket_ms / 1000.0,
                nat_tolerant,
                rtp_rate,
            )

            GLib.idle_add(self._log, "Comparaison baseline / courant...")
            findings = diff_reports(
                baseline_report,
                current_report,
                loss_min_pp=loss_min_pp,
                latency_min_ms=latency_min_ms,
            )

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                print_diff_report(findings)

            tls_findings_baseline = tls_findings_current = None
            quic_findings_baseline = quic_findings_current = None

            if tls:
                GLib.idle_add(self._log, "Diagnostic TLS (relecture des captures via tshark)...")
                from netcross_core.tls_diagnostics import (
                    build_handshake_status,
                    diagnose_tls,
                    parse_tls_capture,
                    print_tls_diagnostics,
                )

                def _tls_findings(captures):
                    events = []
                    for label, path in captures:
                        events.extend(parse_tls_capture(label, path))
                    return diagnose_tls(build_handshake_status(events), points_order)

                tls_findings_baseline = _tls_findings(baseline_captures)
                tls_findings_current = _tls_findings(current_captures)
                with contextlib.redirect_stdout(buf):
                    print("\n" + "=" * 70)
                    print("DIAGNOSTIC TLS -- BASELINE")
                    print("=" * 70)
                    print_tls_diagnostics(tls_findings_baseline)
                    print("\n" + "=" * 70)
                    print("DIAGNOSTIC TLS -- COURANT")
                    print("=" * 70)
                    print_tls_diagnostics(tls_findings_current)

            if quic:
                GLib.idle_add(self._log, "Diagnostic QUIC (relecture des captures via tshark)...")
                try:
                    from netcross_core.quic_diagnostics import (
                        diagnose_quic,
                        parse_quic_capture,
                        print_quic_diagnostics,
                    )
                except ImportError:
                    with contextlib.redirect_stdout(buf):
                        print("\n--quic necessite cryptography : pip install cryptography --break-system-packages")
                else:

                    def _quic_findings(captures):
                        events = []
                        for label, path in captures:
                            events.extend(parse_quic_capture(label, path))
                        return diagnose_quic(events, points_order)

                    quic_findings_baseline = _quic_findings(baseline_captures)
                    quic_findings_current = _quic_findings(current_captures)
                    with contextlib.redirect_stdout(buf):
                        print("\n" + "=" * 70)
                        print("DIAGNOSTIC QUIC/HTTP3 -- BASELINE")
                        print("=" * 70)
                        print_quic_diagnostics(quic_findings_baseline)
                        print("\n" + "=" * 70)
                        print("DIAGNOSTIC QUIC/HTTP3 -- COURANT")
                        print("=" * 70)
                        print_quic_diagnostics(quic_findings_current)

            text = buf.getvalue()
        except Exception as e:  # noqa: BLE001 -- thread de fond (comparaison baseline/courant) : idem.
            GLib.idle_add(self._log, f"ERREUR : {e}")
            GLib.idle_add(self._on_analysis_error, str(e))
            return
        GLib.idle_add(self._log, "Comparaison terminee.")
        GLib.idle_add(
            self._on_diff_done,
            findings,
            baseline_report,
            current_report,
            text,
            tls_findings_baseline,
            tls_findings_current,
            quic_findings_baseline,
            quic_findings_current,
        )

    def _on_analysis_error(self, message):
        self.spinner.stop()
        self.work_status_label.set_text(f"Erreur : {message}")
        self.run_btn.set_sensitive(True)
        return False

    def _on_analysis_done(
        self,
        mode,
        report,
        flows,
        findings,
        text,
        tls_findings=None,
        quic_findings=None,
        wireshark_expert_events=None,
    ):
        self.last_mode = mode
        self.last_report = report
        self.last_flows = flows
        self.last_findings = findings
        self.last_tls_findings = tls_findings
        self.last_quic_findings = quic_findings
        # Signaux tshark bruts : calcules dans le thread d'analyse, ou les
        # paquets sont encore disponibles (issue #14). On garde le RESULTAT
        # plutot que les paquets : conserver `all_packets` dans la fenetre
        # pour un export JSON eventuel immobiliserait la capture entiere en
        # memoire jusqu'a l'analyse suivante.
        self.last_wireshark_expert_events = wireshark_expert_events
        self.last_diff_findings = None
        self.last_baseline_report = None
        self.last_current_report = None
        self.last_diff_tls_findings_baseline = None
        self.last_diff_tls_findings_current = None
        self.last_diff_quic_findings_baseline = None
        self.last_diff_quic_findings_current = None
        self.spinner.stop()
        self.work_status_label.set_text("Analyse terminee.")
        self.result_view.get_buffer().set_text(text)
        self.status_label.set_text("Analyse terminee.")
        self.run_btn.set_sensitive(True)
        self.pdf_btn.set_sensitive(True)
        self.csv_btn.set_sensitive(True)
        self.json_btn.set_sensitive(True)
        self.stack.set_visible_child_name("results")
        return False

    def _on_diff_done(
        self,
        findings,
        baseline_report,
        current_report,
        text,
        tls_findings_baseline=None,
        tls_findings_current=None,
        quic_findings_baseline=None,
        quic_findings_current=None,
    ):
        self.last_mode = "diff"
        self.last_report = None
        self.last_flows = None
        self.last_findings = None
        self.last_tls_findings = None
        self.last_quic_findings = None
        self.last_wireshark_expert_events = None
        self.last_diff_findings = findings
        self.last_baseline_report = baseline_report
        self.last_current_report = current_report
        self.last_diff_tls_findings_baseline = tls_findings_baseline
        self.last_diff_tls_findings_current = tls_findings_current
        self.last_diff_quic_findings_baseline = quic_findings_baseline
        self.last_diff_quic_findings_current = quic_findings_current
        self.spinner.stop()
        self.work_status_label.set_text("Comparaison terminee.")
        self.result_view.get_buffer().set_text(text)
        regressions = sum(1 for f in findings if f.severity == "regression")
        self.status_label.set_text(
            f"Comparaison terminee -- {regressions} regression(s) detectee(s)."
            if regressions
            else "Comparaison terminee -- aucune regression."
        )
        self.run_btn.set_sensitive(True)
        self.pdf_btn.set_sensitive(True)
        self.csv_btn.set_sensitive(True)
        self.json_btn.set_sensitive(True)
        self.stack.set_visible_child_name("results")
        return False

    # ================= export CSV =================

    def on_export_csv(self, _btn):
        if self.last_mode is None:
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("details_flux.csv" if self.last_mode == "single" else "ecarts.csv")
        dialog.save(self, None, self._on_csv_path_chosen)

    def _on_csv_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            return
        path = gfile.get_path()
        try:
            if self.last_mode == "single":
                write_detail_csv(path, self.last_flows, self.last_report.points)
            else:
                write_diff_csv(self.last_diff_findings, path)
        except Exception as e:  # noqa: BLE001 -- callback GUI (export CSV) : erreur affichee dans la barre de statut plutot que de faire planter l'appli.
            self.status_label.set_text(f"Erreur CSV : {e}")
            return
        self.status_label.set_text(f"CSV ecrit : {path}")

    # ================= export PDF =================

    def on_export_pdf(self, _btn):
        if self.last_mode is None:
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("rapport_analyse.pdf" if self.last_mode == "single" else "rapport_comparaison.pdf")
        dialog.save(self, None, self._on_pdf_path_chosen)

    def _on_pdf_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            return
        self.export_pdf_to(gfile.get_path())

    def export_pdf_to(self, path):
        """Separe de la callback du dialogue pour pouvoir etre pilote directement (tests)."""
        self.status_label.set_text("Generation du PDF...")
        threading.Thread(target=self._generate_pdf_thread, args=(path,), daemon=True).start()

    def _session_objects(self):
        """Objets enrichis du dernier run single (issue #14) : memes objets
        que ceux de la CLI, construits par le meme point de passage
        (netcross_report.session_objects) pour que le JSON et le PDF de la
        GUI portent exactement les memes cles et sections.

        `findings` est recalcule ici quand l'utilisateur n'a pas coche le
        triage : ils sont la matiere premiere des ExpertEvent/Diagnosis, et
        `generate_json_report()`/`generate_pdf()` les recalculent de toute
        facon dans ce cas -- autant les calculer une fois et les partager.
        Les signaux tshark, eux, ne sont jamais recalcules : ils viennent du
        thread d'analyse (les paquets bruts ne sont plus disponibles ici).
        """
        from netcross_report import build_findings, build_session_objects

        findings = self.last_findings if self.last_findings is not None else build_findings(self.last_report)
        return build_session_objects(
            self.last_report,
            findings,
            flows=self.last_flows,
            wireshark_expert_events=self.last_wireshark_expert_events,
        )

    def _generate_pdf_thread(self, path):
        try:
            if self.last_mode == "single":
                from netcross_report import generate_pdf

                if generate_pdf is None:
                    raise ImportError("reportlab/matplotlib/networkx requis pour l'export PDF")
                generate_pdf(
                    self.last_report,
                    path,
                    findings=self.last_findings,
                    tls_findings=self.last_tls_findings,
                    quic_findings=self.last_quic_findings,
                    session_objects=self._session_objects(),
                )
            else:
                from netcross_report import generate_diff_pdf

                if generate_diff_pdf is None:
                    raise ImportError("reportlab/matplotlib/networkx requis pour l'export PDF")
                generate_diff_pdf(
                    self.last_diff_findings,
                    self.last_baseline_report,
                    self.last_current_report,
                    path,
                    tls_findings_baseline=self.last_diff_tls_findings_baseline,
                    tls_findings_current=self.last_diff_tls_findings_current,
                    quic_findings_baseline=self.last_diff_quic_findings_baseline,
                    quic_findings_current=self.last_diff_quic_findings_current,
                )
        except Exception as e:  # noqa: BLE001 -- thread de fond (export PDF) : idem, erreur affichee via GLib.idle_add.
            GLib.idle_add(self._on_pdf_error, str(e))
            return
        GLib.idle_add(self._on_pdf_done, path)

    def _on_pdf_error(self, message):
        self.status_label.set_text(f"Erreur PDF : {message}")
        return False

    def _on_pdf_done(self, path):
        self.status_label.set_text(f"PDF ecrit : {path}")
        return False

    # ================= export JSON =================
    # Pendant de on_export_pdf/on_export_csv (Session 37 -- jusque-la
    # absent de la GUI, voir FEATURES.md). netcross_report.json_report est
    # du pur Python (aucune dependance externe, contrairement a
    # generate_pdf) -- pas besoin de garde ImportError equivalente.

    def on_export_json(self, _btn):
        if self.last_mode is None:
            return
        dialog = Gtk.FileDialog()
        dialog.set_initial_name("rapport_analyse.json" if self.last_mode == "single" else "rapport_comparaison.json")
        dialog.save(self, None, self._on_json_path_chosen)

    def _on_json_path_chosen(self, dialog, result):
        try:
            gfile = dialog.save_finish(result)
        except GLib.Error:
            return
        self.export_json_to(gfile.get_path())

    def export_json_to(self, path):
        """Separe de la callback du dialogue pour pouvoir etre pilote directement (tests)."""
        self.status_label.set_text("Generation du JSON...")
        threading.Thread(target=self._generate_json_thread, args=(path,), daemon=True).start()

    def _generate_json_thread(self, path):
        try:
            if self.last_mode == "single":
                from netcross_report import generate_json_report

                generate_json_report(
                    self.last_report,
                    path,
                    findings=self.last_findings,
                    tls_findings=self.last_tls_findings,
                    quic_findings=self.last_quic_findings,
                    **self._session_objects().json_kwargs(),
                )
            else:
                from netcross_report import generate_json_diff

                generate_json_diff(
                    self.last_diff_findings,
                    self.last_baseline_report,
                    self.last_current_report,
                    path,
                    tls_findings_baseline=self.last_diff_tls_findings_baseline,
                    tls_findings_current=self.last_diff_tls_findings_current,
                    quic_findings_baseline=self.last_diff_quic_findings_baseline,
                    quic_findings_current=self.last_diff_quic_findings_current,
                )
        except Exception as e:  # noqa: BLE001 -- thread de fond (export JSON) : idem, erreur affichee via GLib.idle_add.
            GLib.idle_add(self._on_json_error, str(e))
            return
        GLib.idle_add(self._on_json_done, path)

    def _on_json_error(self, message):
        self.status_label.set_text(f"Erreur JSON : {message}")
        return False

    def _on_json_done(self, path):
        self.status_label.set_text(f"JSON ecrit : {path}")
        return False


class NetcrossApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.netcross.analyzer")
        self.main_window = None

    def do_activate(self):
        if not self.main_window:
            self.main_window = MainWindow(self)
        self.main_window.present()


def main():
    app = NetcrossApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
