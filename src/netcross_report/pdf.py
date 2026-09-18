"""
netcross_report.pdf -- assemble le rapport PDF final (synthese, graphiques,
tableaux de detail) a partir d'un Report netcross_core, avec reportlab.
"""

import datetime
import tempfile

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from netcross_report.charts import DIFF_SEVERITY_SCHEME, chart_severity_summary, generate_all_charts
from netcross_report.synthesis import build_findings
from netcross_report.triage import HEALTH_LABELS, health_label, health_score, rank_segments

SEVERITY_LABELS = {
    "anomalie": "Anomalie",
    "a_surveiller": "A surveiller",
    "info": "Info",
    # vocabulaire de baseline_diff.DiffFinding -- meme table de rendu
    # (_finding_table) reutilisee pour le rapport PDF de diff, voir
    # generate_diff_pdf() plus bas
    "regression": "Regression",
    "a_verifier": "A verifier",
    "amelioration": "Amelioration",
    "stable": "Stable",
}
SEVERITY_COLORS = {
    "anomalie": colors.HexColor("#ef4444"),
    "a_surveiller": colors.HexColor("#f59e0b"),
    "info": colors.HexColor("#94a3b8"),
    "regression": colors.HexColor("#ef4444"),
    "a_verifier": colors.HexColor("#f59e0b"),
    "amelioration": colors.HexColor("#22c55e"),
    "stable": colors.HexColor("#94a3b8"),
}

# Couleurs du badge "Score de sante" -- memes 4 tranches que
# netcross_report.triage.HEALTH_LABEL_THRESHOLDS, palette coherente avec
# SEVERITY_COLORS ci-dessus (rouge = anomalie/critique, ambre = a
# surveiller, vert reserve a "bon" ici -- amelioration l'utilise deja pour
# le vocabulaire diff, pas de collision possible : les deux ne
# s'affichent jamais dans le meme badge).
HEALTH_BADGE_COLORS = {
    "bon": colors.HexColor("#22c55e"),
    "a_surveiller": colors.HexColor("#f59e0b"),
    "degrade": colors.HexColor("#f97316"),
    "critique": colors.HexColor("#ef4444"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("H1b", parent=styles["Heading1"], spaceBefore=18, spaceAfter=8))
    styles.add(ParagraphStyle("H2b", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6))
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, textColor=colors.grey))
    return styles


def _finding_table(findings, styles):
    if not findings:
        return Paragraph("Aucun constat notable.", styles["Normal"])
    data = [["Gravite", "Categorie", "Segment", "Constat"]]
    data.extend(
        [
            SEVERITY_LABELS[f.severity],
            f.category,
            Paragraph(f.segment, styles["Normal"]),
            Paragraph(f.message, styles["Normal"]),
        ]
        for f in findings
    )
    t = Table(data, colWidths=[2.4 * cm, 2.6 * cm, 2.8 * cm, 8.5 * cm], repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#f9fafb")],
        ),
    ]
    for i, f in enumerate(findings, start=1):
        style.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS[f.severity]))
        style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style))
    return t


def _triage_table(ranked, styles, top_n=10):
    """ranked : liste de netcross_report.triage.SegmentScore, deja triee
    par score decroissant (rank_segments()). N'affiche que les segments
    convergents (>=2 categories) -- un segment avec un seul constat
    isole n'apporte rien de plus que ce que la table de constats montre
    deja, ce n'est pas ca qui doit orienter "par ou commencer"."""
    convergent = [s for s in ranked if s.convergent]
    if not convergent:
        return Paragraph(
            "Aucun segment touche par plusieurs categories de constats a la fois "
            "-- pas de faisceau de preuves a signaler ici, voir la table de constats "
            "ci-dessous pour le detail exhaustif.",
            styles["Normal"],
        )
    data = [["Segment", "Score", "Categories touchees", "Constats"]]
    data.extend(
        [
            Paragraph(
                s.segment + (" (echantillon faible)" if s.low_confidence else ""),
                styles["Normal"],
            ),
            f"{s.score:.1f}",
            Paragraph(", ".join(s.categories), styles["Normal"]),
            str(len(s.findings)),
        ]
        for s in convergent[:top_n]
    )
    t = Table(data, colWidths=[3.5 * cm, 1.8 * cm, 7.7 * cm, 2.3 * cm], repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f9fafb")],
                ),
            ]
        )
    )
    return t


def _health_badge(ranked, styles):
    """Paragraphe compact affiche juste au-dessus de la table de triage --
    condense la meme donnee (rank_segments()) en un seul chiffre pour une
    lecture en un coup d'oeil. Voir netcross_report.triage.health_score
    pour la formule et la note de conception (notamment sur ce que le
    score signifie quand `ranked` vient d'un diff plutot que d'un run
    simple)."""
    score = health_score(ranked)
    label = health_label(score)
    style = ParagraphStyle(
        "HealthBadge",
        parent=styles["Normal"],
        fontSize=13,
        fontName="Helvetica-Bold",
        textColor=HEALTH_BADGE_COLORS[label],
        spaceAfter=6,
    )
    return Paragraph(f"Score de sante : {score}/100 -- {HEALTH_LABELS[label]}", style)


def _kv_table(rows, styles, col_widths=None):
    data = [[Paragraph(str(a), styles["Normal"]), Paragraph(str(b), styles["Normal"])] for a, b in rows]
    t = Table(data, colWidths=col_widths or [5 * cm, 10 * cm])
    t.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
            ]
        )
    )
    return t


def generate_pdf(
    r,
    output_path,
    title="Analyse croisee de captures reseau",
    meta=None,
    findings=None,
    tls_findings=None,
    quic_findings=None,
):
    """
    r : objet Report (netcross_core.analyse). output_path : chemin du PDF.
    meta : dict optionnel de metadonnees a afficher en page de garde
    (ex: {"Ticket": "INC-1234", "Auteur": "Mathilde"}).
    findings : liste de Finding deja calculee (synthesis.build_findings(r))
    si l'appelant l'a deja fait (evite un recalcul) ; sinon calculee ici.
    tls_findings / quic_findings : listes de TlsFinding optionnelles
    (netcross_core.tls_diagnostics.diagnose_tls / quic_diagnostics.diagnose_quic).
    Si fournies : affichees dans une section dediee ET integrees au triage
    "par ou commencer" en tete de rapport (memes categories/segments que les
    constats principaux -- rank_segments() est concu pour un melange des
    deux, voir netcross_report/triage.py).
    """
    if findings is None:
        findings = build_findings(r)
    ranked = rank_segments(list(findings) + list(tls_findings or []) + list(quic_findings or []))

    with tempfile.TemporaryDirectory() as tmpdir:
        charts = generate_all_charts(r, findings, tmpdir)
        styles = _styles()
        story = []

        # -- page de garde --
        story.append(Spacer(1, 3 * cm))
        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 0.5 * cm))
        now = datetime.datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
        info_rows = [("Genere le", now), ("Points de capture", ", ".join(r.points))]
        if meta:
            seen_keys = {k for k, _ in info_rows}
            info_rows += [(k, v) for k, v in meta.items() if k not in seen_keys]
        story.append(_kv_table(info_rows, styles))
        story.append(PageBreak())

        # -- par ou commencer (triage) --
        story.append(Paragraph("Par ou commencer", styles["H1b"]))
        story.append(
            Paragraph(
                "Segments touches par au moins 2 categories de constats differentes en "
                "meme temps -- signature d'un faisceau de preuves convergent plutot que "
                "d'un indice isole. Ne remplace pas la lecture complete des sections "
                "suivantes, mais indique par ou commencer a regarder.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        story.append(_health_badge(ranked, styles))
        story.append(_triage_table(ranked, styles))
        story.append(PageBreak())

        # -- synthese --
        story.append(Paragraph("Synthese", styles["H1b"]))
        n_anom = sum(1 for f in findings if f.severity == "anomalie")
        n_surv = sum(1 for f in findings if f.severity == "a_surveiller")
        story.append(
            Paragraph(
                f"{n_anom} anomalie(s) et {n_surv} point(s) a surveiller identifies "
                f"automatiquement a partir des seuils definis dans l'outil. Chaque ligne "
                f"renvoie a un chiffre mesure, detaille dans les sections suivantes.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        if "severity" in charts:
            story.append(Image(charts["severity"], width=8 * cm, height=6 * cm))
        story.append(Spacer(1, 0.3 * cm))
        story.append(_finding_table(findings, styles))
        story.append(PageBreak())

        # -- vue d'ensemble graphique --
        story.append(Paragraph("Vue d'ensemble", styles["H1b"]))
        if "topology" in charts:
            story.append(Paragraph("Topologie deduite", styles["H2b"]))
            from PIL import Image as PILImage

            with PILImage.open(charts["topology"]) as im:
                img_w, img_h = im.size
            max_w, max_h = 16 * cm, 13 * cm
            ratio = min(max_w / img_w, max_h / img_h)
            story.append(Image(charts["topology"], width=img_w * ratio, height=img_h * ratio))
            story.append(Spacer(1, 0.3 * cm))
        for key, caption in [
            ("throughput", "Debit par point"),
            ("latency", "Latence par segment"),
            ("loss", "Pertes par point"),
        ]:
            if key in charts:
                story.append(Paragraph(caption, styles["H2b"]))
                story.append(Image(charts[key], width=14 * cm, height=7 * cm))
                story.append(Spacer(1, 0.3 * cm))
        story.append(PageBreak())

        # -- graphiques temporels top-N (protocole/port/IP/DSCP) --
        # un seul point trace (voir netcross_report.charts.generate_topn_charts
        # et chart_topn_timeseries pour le choix documente) -- absent du
        # dict `charts` si r.topn_timeseries est vide (all_packets vide) ou
        # si aucune des 4 dimensions n'a produit de graphique pour ce point.
        topn_keys = [k for k in charts if k.startswith("topn_")]
        if topn_keys:
            topn_point = r.points[0] if r.points else "?"
            story.append(Paragraph("Evolution temporelle (top-N)", styles["H1b"]))
            story.append(
                Paragraph(
                    f"Debit ventile par categorie au fil du temps, point {topn_point} uniquement "
                    "(voir la documentation pour les captures a plusieurs points : additionner "
                    "plusieurs points sur un meme graphique compterait certains paquets en double). "
                    'Les categories les moins volumineuses sont regroupees sous "autres".',
                    styles["Normal"],
                )
            )
            story.append(Spacer(1, 0.3 * cm))
            for dimension, caption in [
                ("protocol", "Par protocole"),
                ("port", "Par port de destination"),
                ("ip", "Par IP de destination"),
                ("dscp", "Par marquage DSCP"),
            ]:
                key = f"topn_{dimension}"
                if key in charts:
                    story.append(Paragraph(caption, styles["H2b"]))
                    story.append(Image(charts[key], width=16 * cm, height=6 * cm))
                    story.append(Spacer(1, 0.3 * cm))
            story.append(PageBreak())

        # -- detail par module --
        story.append(Paragraph("Detail par module", styles["H1b"]))

        story.append(Paragraph("Sauts de routeur (delta TTL)", styles["H2b"]))
        rows = []
        for a, b in r.pairs:
            deltas = r.hop_delta.get((a, b))
            if not deltas:
                continue
            from collections import Counter

            mode_delta, mode_n = Counter(deltas).most_common(1)[0]
            rows.append(
                (
                    f"{a} -> {b}",
                    f"{abs(mode_delta)} saut(s) ({mode_n}/{len(deltas)} flux)",
                )
            )
        if rows:
            story.append(_kv_table(rows, styles))
        else:
            story.append(Paragraph("Aucune donnee.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("QoS (DSCP)", styles["H2b"]))
        rows = [(f"{a} -> {b}", f"{n} paquet(s) remarque(s)") for (a, b), n in r.qos_change.items() if n]
        story.append(_kv_table(rows, styles) if rows else Paragraph("Aucun changement.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("Fragmentation / MTU", styles["H2b"]))
        rows = [
            (f"{a} -> {b}", f"{n} datagramme(s) nouvellement fragmente(s)") for (a, b), n in r.frag_new.items() if n
        ]
        story.append(_kv_table(rows, styles) if rows else Paragraph("Aucune fragmentation.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("Encapsulation / tunnels", styles["H2b"]))
        rows = []
        for p in r.points:
            stacks = sorted(r.encap_seen.get(p, []))
            if stacks:
                rows.append((p, ", ".join(stacks)))
        story.append(_kv_table(rows, styles) if rows else Paragraph("Aucun tunnel detecte.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph("TCP avance", styles["H2b"]))
        rows = []
        for p in r.points:
            if r.zero_window.get(p):
                rows.append((f"{p} : fenetre=0", r.zero_window[p]))
            if r.dup_ack.get(p):
                rows.append((f"{p} : ACK dupliques", r.dup_ack[p]))
            if r.rst_count.get(p):
                rows.append((f"{p} : RST", r.rst_count[p]))
            if r.retrans.get(p):
                rows.append((f"{p} : retransmissions", r.retrans[p]))
        story.append(_kv_table(rows, styles) if rows else Paragraph("Rien de notable.", styles["Normal"]))
        story.append(Spacer(1, 0.3 * cm))

        if r.rtp_streams:
            story.append(Paragraph("Flux RTP (voix/visio)", styles["H2b"]))
            data = [["Flux", "Perte", "Delai", "MOS"]]
            for s in r.rtp_streams[:30]:
                last_point = r.points[-1] if r.points else None
                loss = s["loss_pct"].get(last_point, 0.0) if last_point else 0.0
                short_label = s["label"].split(" (SSRC=")[0]
                data.append(
                    [
                        Paragraph(short_label, styles["Normal"]),
                        f"{loss:.1f}%",
                        f"{s['delay_ms']:.0f}ms" if s["delay_ms"] is not None else "-",
                        f"{s['mos']:.2f}" if s["mos"] is not None else "-",
                    ]
                )
            t = Table(data, colWidths=[7 * cm, 2.5 * cm, 2.5 * cm, 2.5 * cm])
            t.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                    ]
                )
            )
            story.append(t)
            story.append(Spacer(1, 0.3 * cm))

        if r.dhcp_msg_count:
            story.append(Paragraph("DHCP", styles["H2b"]))
            rows = []
            for p in r.points:
                counts = r.dhcp_msg_count.get(p, {})
                if counts:
                    rows.append((p, ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))))
            story.append(_kv_table(rows, styles) if rows else Paragraph("Rien.", styles["Normal"]))
            story.append(Spacer(1, 0.3 * cm))

        if r.sip_msg_count:
            story.append(Paragraph("SIP", styles["H2b"]))
            rows = []
            for p in r.points:
                counts = r.sip_msg_count.get(p, {})
                if counts:
                    rows.append((p, ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))))
            story.append(_kv_table(rows, styles) if rows else Paragraph("Rien.", styles["Normal"]))

        if tls_findings or quic_findings:
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph("Diagnostics TLS / QUIC", styles["H2b"]))
            story.append(
                Paragraph(
                    "Pipeline de decodage independant qui relit les memes captures "
                    "(voir netcross_core.tls_diagnostics / quic_diagnostics) -- ces "
                    "constats sont deja inclus dans le triage en tete de rapport.",
                    styles["Small"],
                )
            )
            story.append(Spacer(1, 0.2 * cm))
            if tls_findings:
                story.append(Paragraph("TLS", styles["Heading3"]))
                story.append(_finding_table(tls_findings, styles))
                story.append(Spacer(1, 0.3 * cm))
            if quic_findings:
                story.append(Paragraph("QUIC / HTTP3", styles["Heading3"]))
                story.append(_finding_table(quic_findings, styles))

        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
        story.append(
            Paragraph(
                "Rapport genere automatiquement par cross_capture_analyzer (netcross). "
                "Les verdicts de saturation/policing/bufferbloat/injection sont des indices "
                "statistiques, a confirmer avec les journaux des equipements suspectes.",
                styles["Small"],
            )
        )

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
        )
        doc.build(story)

    return output_path


def generate_diff_pdf(
    findings,
    baseline,
    current,
    output_path,
    title="Comparaison avant / apres",
    meta=None,
    tls_findings_baseline=None,
    tls_findings_current=None,
    quic_findings_baseline=None,
    quic_findings_current=None,
):
    """
    Rapport PDF pour un diff baseline_diff.diff_reports() -- pendant de
    generate_pdf() pour DiffFinding plutot que Finding. Plus court : pas
    de vue d'ensemble graphique (topologie/debit/latence/pertes propres
    a UN Report), seulement triage + synthese + table de constats,
    puisque c'est baseline_diff qui a deja fait le travail de comparaison
    chiffre entre les deux Report.

    findings : liste de DiffFinding (baseline_diff.diff_reports()).
    baseline, current : les deux Report compares (pour la page de garde
    uniquement -- listes de points).
    tls_findings_baseline / tls_findings_current / quic_findings_baseline /
    quic_findings_current : listes de TlsFinding optionnelles
    (netcross_core.tls_diagnostics.diagnose_tls / quic_diagnostics.diagnose_quic),
    executees separement sur le baseline et sur le run courant par
    l'appelant (cross_capture_diff_cli.py --tls/--quic). Affichees dans
    une section dediee, baseline et courant l'un sous l'autre -- PAS
    fondues dans le triage/la table de constats ci-dessus : ces deux
    modules ne connaissent qu'un etat a un instant donne (severites
    anomalie/a_surveiller/info), pas une paire avant/apres comme
    DiffFinding (regression/a_verifier/amelioration) ; les melanger aurait
    fausse le decompte de _severity_ affiche dans le graphique de synthese
    (chart_severity_summary, vocabulaire DIFF_SEVERITY_SCHEME) sans
    apporter de vraie semantique de diff en echange. Voir claude.md pour
    la discussion complete de ce choix.
    """
    ranked = rank_segments(findings)

    with tempfile.TemporaryDirectory() as tmpdir:
        styles = _styles()
        story = []

        # -- page de garde --
        story.append(Spacer(1, 3 * cm))
        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 0.5 * cm))
        now = datetime.datetime.now().astimezone().strftime("%d/%m/%Y %H:%M")
        info_rows = [
            ("Genere le", now),
            ("Points baseline", ", ".join(baseline.points)),
            ("Points courant", ", ".join(current.points)),
        ]
        if meta:
            seen_keys = {k for k, _ in info_rows}
            info_rows += [(k, v) for k, v in meta.items() if k not in seen_keys]
        story.append(_kv_table(info_rows, styles))
        story.append(PageBreak())

        # -- par ou commencer (triage) --
        story.append(Paragraph("Par ou commencer", styles["H1b"]))
        story.append(
            Paragraph(
                "Segments cumulant le plus d'ecarts (regressions et points a verifier "
                "pesant plus qu'une amelioration), et/ou touches par plusieurs "
                "categories a la fois.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        story.append(_health_badge(ranked, styles))
        story.append(_triage_table(ranked, styles))
        story.append(PageBreak())

        # -- constats --
        story.append(Paragraph("Constats", styles["H1b"]))
        n_reg = sum(1 for f in findings if f.severity == "regression")
        n_ver = sum(1 for f in findings if f.severity == "a_verifier")
        n_ame = sum(1 for f in findings if f.severity == "amelioration")
        story.append(
            Paragraph(
                f"{n_reg} regression(s), {n_ver} point(s) a verifier, {n_ame} "
                f"amelioration(s) identifies entre les deux runs.",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 0.3 * cm))
        chart_path = f"{tmpdir}/chart_severity.png"
        if chart_severity_summary(findings, chart_path, scheme=DIFF_SEVERITY_SCHEME):
            story.append(Image(chart_path, width=8 * cm, height=6 * cm))
        story.append(Spacer(1, 0.3 * cm))
        story.append(_finding_table(findings, styles))

        if tls_findings_baseline or tls_findings_current or quic_findings_baseline or quic_findings_current:
            story.append(PageBreak())
            story.append(Paragraph("Diagnostics TLS / QUIC -- baseline vs courant", styles["H1b"]))
            story.append(
                Paragraph(
                    "Pipeline de decodage independant, execute separement sur le baseline "
                    "et sur le run courant (voir netcross_core.tls_diagnostics / "
                    "quic_diagnostics) -- pas de diff semantique entre les deux, ces deux "
                    "modules ne connaissent qu'un etat a un instant donne. Comparer les "
                    "deux sous-sections a l'oeil plutot que de chercher un ecart chiffre.",
                    styles["Small"],
                )
            )
            story.append(Spacer(1, 0.3 * cm))
            if tls_findings_baseline or tls_findings_current:
                story.append(Paragraph("TLS -- Baseline", styles["Heading3"]))
                story.append(_finding_table(tls_findings_baseline or [], styles))
                story.append(Spacer(1, 0.2 * cm))
                story.append(Paragraph("TLS -- Courant", styles["Heading3"]))
                story.append(_finding_table(tls_findings_current or [], styles))
                story.append(Spacer(1, 0.3 * cm))
            if quic_findings_baseline or quic_findings_current:
                story.append(Paragraph("QUIC/HTTP3 -- Baseline", styles["Heading3"]))
                story.append(_finding_table(quic_findings_baseline or [], styles))
                story.append(Spacer(1, 0.2 * cm))
                story.append(Paragraph("QUIC/HTTP3 -- Courant", styles["Heading3"]))
                story.append(_finding_table(quic_findings_current or [], styles))

        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
        story.append(
            Paragraph(
                "Rapport de comparaison genere automatiquement par cross_capture_diff "
                "(netcross). Chaque ecart releve un seuil explicite (voir "
                "netcross_core.baseline_diff) ; a confirmer avec le contexte operationnel "
                "(changement volontaire, charge differente entre les deux runs...).",
                styles["Small"],
            )
        )

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
        )
        doc.build(story)

    return output_path
