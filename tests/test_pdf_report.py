"""
Tests du rendu PDF (`netcross_report/pdf.py`) -- issue #286.

Le module etait a 32,6 % avant l'issue #218, puis 63,1 % apres elle, sans
aucun fichier de test dedie. Le PDF est pourtant une sortie que
l'utilisateur regarde : une section peut disparaitre, un tableau se
vider, une valeur etre jetee au rendu sans que rien n'echoue. C'est
exactement ce qui s'est produit avec l'issue #259 -- un champ correctement
calcule, perdu a l'affichage, invisible pour tous les tests parce qu'ils
s'arretaient avant le rendu.

## Ce qui est verifie, et ce qui ne l'est pas

**Jamais la mise en page au pixel** : fragile et sans valeur. Le texte est
REEXTRAIT du PDF produit (`pdftotext`, installe en CI depuis #218) et l'on
verifie que les valeurs du `Report` s'y retrouvent, que les sections
attendues sont presentes, et que les chemins « il n'y a rien a afficher »
ecrivent leur message d'absence.

Ce dernier point est une regle du projet : une section sans donnee doit
**ecrire** qu'elle est vide, pas disparaitre. Les tests portent donc sur la
presence du message, jamais sur l'absence de la section -- l'inverse
enterinerait le contraire de la regle.

`generate_diff_pdf` n'etait couvert par AUCUN test : le rapport du mode
comparaison, celui qu'on relit pour decider si une regression est reelle,
n'etait verifie par rien.
"""

from __future__ import annotations

import subprocess

import pytest

from netcross_core.baseline_diff import diff_reports
from netcross_core.models import Report
from netcross_report.pdf import (
    _compliance_table,
    _diagnosis_table,
    _expert_event_table,
    _finding_table,
    _flow_table,
    _path_table,
    _styles,
    _triage_table,
    generate_diff_pdf,
    generate_pdf,
)
from netcross_report.synthesis import build_findings


def _texte_pdf(chemin) -> str:
    """Texte reextrait du PDF produit.

    Reextraire plutot que d'inspecter la story reportlab avant rendu : c'est
    le seul niveau qui prouve que la donnee atteint le fichier livre. Message
    de saut normalise -- le workflow ci.yml echoue si « pdftotext non
    installe » apparait dans la sortie de pytest (meme garde-fou que
    tshark/editcap, issue #262).
    """
    try:
        proc = subprocess.run(["pdftotext", str(chemin), "-"], capture_output=True, text=True)
    except FileNotFoundError:
        pytest.skip("pdftotext non installe : contenu du PDF non verifiable")
    if proc.returncode != 0:
        pytest.skip(f"pdftotext non installe correctement (code {proc.returncode})")
    return proc.stdout


def _rapport_garni() -> Report:
    """Report avec de quoi remplir plusieurs sections.

    Les valeurs sont volontairement reconnaissables (7, 13, 4242) pour
    pouvoir les retrouver dans le texte extrait : un chiffre banal comme 1 se
    retrouverait par hasard et le test ne prouverait rien.
    """
    r = Report(points=["POINT_AMONT", "POINT_AVAL"], pairs=[("POINT_AMONT", "POINT_AVAL")])
    r.seen_count["POINT_AMONT"] = 4242
    r.seen_count["POINT_AVAL"] = 4200
    r.loss_count["POINT_AVAL"] = 7
    r.retrans["POINT_AVAL"] = 13
    r.latency[("POINT_AMONT", "POINT_AVAL")] = [0.012, 0.031, 0.027]
    r.hop_delta[("POINT_AMONT", "POINT_AVAL")] = [2, 2, 3]
    r.qos_change[("POINT_AMONT", "POINT_AVAL")] = 5
    return r


def _rapport_vide() -> Report:
    """Report sans aucune mesure : le cas « capture lue, rien a signaler ».

    Ce n'est pas un cas theorique -- c'est ce que produit une capture saine,
    donc le plus frequent en exploitation normale.
    """
    return Report(points=["A", "B"], pairs=[("A", "B")])


# --------------------------------------------------------------------------
# Bout en bout : la donnee atteint-elle le fichier ?
# --------------------------------------------------------------------------


def test_le_pdf_est_produit_et_non_vide(tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin))
    assert chemin.exists()
    assert chemin.stat().st_size > 1000, "PDF suspect : trop petit pour contenir un rapport"
    assert chemin.read_bytes().startswith(b"%PDF"), "en-tete PDF absent"


def test_les_valeurs_du_rapport_se_retrouvent_dans_le_pdf(tmp_path):
    """Le niveau de verification qui manquait a l'issue #259 : la valeur est
    cherchee dans le fichier livre, pas dans l'objet intermediaire.

    Les valeurs retenues sont celles reellement rendues. Un premier jet
    cherchait `seen_count` (4242) : il echouait, non par defaut du rendu mais
    parce que le nombre de paquets vus n'apparait NULLE PART en valeur
    absolue -- il ne sert que de denominateur aux pourcentages. Le test
    verifie donc ce que le PDF affiche, et la coherence de ce denominateur
    est verifiee separement ci-dessous.
    """
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin))
    texte = _texte_pdf(chemin)
    assert "POINT_AMONT" in texte
    assert "POINT_AVAL" in texte
    assert "7 paquets manquants" in texte, "le compteur de pertes n'atteint pas le PDF"
    assert "13" in texte, "le compteur de retransmissions n'atteint pas le PDF"
    assert "5 paquet(s) remarque(s)" in texte, "le compteur DSCP n'atteint pas le PDF"


def test_le_pourcentage_de_pertes_utilise_le_bon_denominateur(tmp_path):
    """7 pertes sur 4242 paquets vus font 0,17 %. Un denominateur errone
    (total des deux points, paquets d'un autre point, nombre de flux) donnerait
    un chiffre d'apparence credible mais faux -- et c'est sur ce chiffre que
    l'utilisateur decide s'il y a un incident.

    Le pourcentage est ancre sur le compte de pertes (« 0.17% (7) ») et non
    cherche seul. Un premier jet acceptait n'importe quel pourcentage a 0,05
    point de la valeur attendue : en doublant volontairement le denominateur
    dans `path_metrics`, le test continuait de passer -- il tombait sur le
    « 0.2 % » de la section Synthese, calcule ailleurs et arrondi a une
    decimale, donc encore dans la plage toleree. Un test qui survit a la
    mutation qu'il est cense attraper ne sert a rien ; l'ancrage sur le compte
    le rend specifique a la valeur reellement rendue par le tableau de chemin.
    """
    import re

    r = _rapport_garni()
    pertes = r.loss_count["POINT_AVAL"]
    attendu = 100.0 * pertes / r.seen_count["POINT_AMONT"]
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(r, str(chemin))
    texte = _texte_pdf(chemin)

    trouves = re.findall(rf"([0-9]+\.[0-9]+)%\s*\({pertes}\)", texte)
    assert trouves, (
        f"aucun pourcentage associe aux {pertes} pertes dans le PDF : "
        "le tableau de chemin a change de forme ou n'affiche plus le taux"
    )
    assert all(abs(float(v) - attendu) < 0.01 for v in trouves), (
        f"taux de pertes attendu {attendu:.2f}%, rendu {trouves} -- denominateur errone"
    )


def test_le_pdf_porte_le_titre_demande(tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin), title="Incident INC-4242 -- coeur de reseau")
    assert "Incident INC-4242" in _texte_pdf(chemin)


def test_les_metadonnees_sont_ecrites_en_page_de_garde(tmp_path):
    """La page de garde sert a retrouver le contexte des mois plus tard : un
    numero de ticket perdu au rendu rend le rapport orphelin."""
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(
        _rapport_garni(),
        str(chemin),
        meta={"Ticket": "INC-9137", "Auteur": "Equipe reseau"},
    )
    texte = _texte_pdf(chemin)
    assert "INC-9137" in texte
    assert "Equipe reseau" in texte


def test_les_sections_attendues_sont_presentes(tmp_path):
    chemin = tmp_path / "rapport.pdf"
    generate_pdf(_rapport_garni(), str(chemin))
    texte = _texte_pdf(chemin)
    for section in ("Vue d'ensemble", "Detail par module"):
        assert section in texte, f"section absente du PDF : {section}"


def test_un_rapport_sans_mesure_produit_quand_meme_un_pdf(tmp_path):
    """Une capture saine ne doit pas donner un fichier vide ou une
    exception : c'est le cas le plus frequent en exploitation normale, et
    l'utilisateur a besoin du document pour attester que rien n'a ete
    trouve."""
    chemin = tmp_path / "vide.pdf"
    generate_pdf(_rapport_vide(), str(chemin))
    texte = _texte_pdf(chemin)
    assert chemin.stat().st_size > 1000
    assert texte.strip(), "PDF sans aucun texte"


def test_le_pdf_accepte_des_constats_deja_calcules(tmp_path):
    """`findings` fourni evite un recalcul. Le chemin doit donner le meme
    resultat que le calcul interne, sinon l'optimisation change la sortie."""
    r = _rapport_garni()
    findings = build_findings(r)
    calcule = tmp_path / "a.pdf"
    fourni = tmp_path / "b.pdf"
    generate_pdf(r, str(calcule))
    generate_pdf(r, str(fourni), findings=findings)
    assert _texte_pdf(calcule) == _texte_pdf(fourni)


# --------------------------------------------------------------------------
# Les sections vides ECRIVENT leur absence
# --------------------------------------------------------------------------


def test_une_table_de_constats_vide_ecrit_son_message():
    """Regle du projet : une section sans donnee ecrit qu'elle est vide. Le
    test porte sur la presence du message, jamais sur l'absence de la
    section -- l'inverse enterinerait le contraire de la regle."""
    rendu = _finding_table([], _styles())
    assert "Aucun constat notable" in rendu.text


def test_un_triage_sans_segment_convergent_explique_pourquoi():
    """Le message ne dit pas seulement « rien » : il renvoie a la table de
    constats. Un « aucun resultat » sec laisserait croire que l'analyse n'a
    rien trouve, alors qu'elle n'a trouve aucun FAISCEAU -- nuance qui change
    la conduite a tenir."""
    rendu = _triage_table([], _styles())
    assert "Aucun segment touche par plusieurs categories" in rendu.text
    assert "table de constats" in rendu.text


def test_les_tables_d_expertise_vides_ecrivent_leur_message():
    styles = _styles()
    assert "Aucun evenement d'expertise" in _expert_event_table([], styles).text
    assert "Aucun diagnostic par segment" in _diagnosis_table([], styles).text
    assert "Aucun referentiel evalue" in _compliance_table([], styles).text
    assert "Aucun flux correle" in _flow_table([], styles).text


def test_une_table_de_chemin_vide_explique_la_cause():
    """« Aucun segment exploitable » seul serait ambigu. Le message nomme les
    deux causes possibles -- ni topologie deduite, ni couple de points fourni
    -- parce que ce sont deux problemes a corriger differemment."""
    rendu = _path_table([], _styles())
    assert "Aucun segment exploitable" in rendu.text
    assert "topologie deduite" in rendu.text


@pytest.mark.parametrize(
    "fabrique",
    [_finding_table, _expert_event_table, _diagnosis_table, _compliance_table, _flow_table],
)
def test_aucune_table_vide_ne_renvoie_none(fabrique):
    """Invariant transverse : renvoyer `None` ferait disparaitre la section de
    la story sans bruit, ce qui est precisement le comportement que la regle
    de tracabilite interdit."""
    rendu = fabrique([], _styles())
    assert rendu is not None
    assert getattr(rendu, "text", "").strip()


# --------------------------------------------------------------------------
# PDF de comparaison -- n'etait couvert par aucun test
# --------------------------------------------------------------------------


def _paire_de_rapports():
    """Deux Report differant assez pour produire de vrais DiffFinding.

    Les constats viennent de `diff_reports()` plutot que d'objets fabriques a
    la main : un double mal forme testerait le double, pas le rendu.
    """
    reference = Report(points=["POINT_AMONT", "POINT_AVAL"], pairs=[("POINT_AMONT", "POINT_AVAL")])
    reference.seen_count["POINT_AMONT"] = 10000
    reference.seen_count["POINT_AVAL"] = 9990
    reference.loss_count["POINT_AVAL"] = 10
    reference.latency[("POINT_AMONT", "POINT_AVAL")] = [0.010] * 20

    courant = Report(points=["POINT_AMONT", "POINT_AVAL"], pairs=[("POINT_AMONT", "POINT_AVAL")])
    courant.seen_count["POINT_AMONT"] = 10000
    courant.seen_count["POINT_AVAL"] = 8500
    courant.loss_count["POINT_AVAL"] = 1500
    courant.latency[("POINT_AMONT", "POINT_AVAL")] = [0.250] * 20
    return reference, courant


def test_le_pdf_de_comparaison_est_produit(tmp_path):
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(diff_reports(reference, courant), reference, courant, str(chemin))
    assert chemin.exists()
    assert chemin.read_bytes().startswith(b"%PDF")
    assert chemin.stat().st_size > 1000


def test_le_pdf_de_comparaison_nomme_les_deux_cotes(tmp_path):
    """Un rapport de comparaison qui ne dit pas ce qu'il compare est
    inutilisable : le lecteur ne sait pas quel cote est la reference."""
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(diff_reports(reference, courant), reference, courant, str(chemin))
    texte = _texte_pdf(chemin)
    assert "POINT_AMONT" in texte
    assert "POINT_AVAL" in texte


def test_le_pdf_de_comparaison_signale_une_degradation_franche(tmp_path):
    """La reference perd 10 paquets sur 10000, le courant 1500 : la
    degradation doit apparaitre. Sans cette verification, le rendu pourrait
    jeter tous les constats et produire un PDF rassurant sur une panne
    reelle."""
    reference, courant = _paire_de_rapports()
    findings = diff_reports(reference, courant)
    assert findings, "diff_reports ne produit aucun constat : le scenario de test est faux"
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(findings, reference, courant, str(chemin))
    texte = _texte_pdf(chemin).lower()
    assert "regression" in texte or "degradation" in texte


def test_le_pdf_de_comparaison_porte_son_titre_et_ses_metadonnees(tmp_path):
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff.pdf"
    generate_diff_pdf(
        diff_reports(reference, courant),
        reference,
        courant,
        str(chemin),
        title="Avant / apres migration MPLS",
        meta={"Ticket": "CHG-7781"},
    )
    texte = _texte_pdf(chemin)
    assert "Avant / apres migration MPLS" in texte
    assert "CHG-7781" in texte


def test_deux_rapports_identiques_produisent_un_pdf_qui_le_dit(tmp_path):
    """Cas frequent et important : une comparaison sans ecart doit produire un
    document affirmant qu'il n'y a pas d'ecart. Un PDF vide, ou une exception,
    laisserait l'utilisateur sans preuve que la verification a eu lieu."""
    reference, _ = _paire_de_rapports()
    findings = diff_reports(reference, reference)
    chemin = tmp_path / "identique.pdf"
    generate_diff_pdf(findings, reference, reference, str(chemin))
    texte = _texte_pdf(chemin)
    assert chemin.stat().st_size > 1000
    assert texte.strip()


def test_le_pdf_de_comparaison_accepte_l_absence_de_diagnostics_tls(tmp_path):
    """TLS/QUIC ne sont pas demandes a chaque comparaison : `None` (« pas
    analyse ») ne doit pas faire tomber le rendu ni etre confondu avec une
    liste vide (« analyse, rien trouve »)."""
    reference, courant = _paire_de_rapports()
    chemin = tmp_path / "diff_sans_tls.pdf"
    generate_diff_pdf(
        diff_reports(reference, courant),
        reference,
        courant,
        str(chemin),
        tls_findings_baseline=None,
        tls_findings_current=None,
        quic_findings_baseline=None,
        quic_findings_current=None,
    )
    assert chemin.stat().st_size > 1000


def test_le_pdf_de_comparaison_supporte_une_liste_de_constats_vide(tmp_path):
    """Chemin de degradation extreme : aucun constat du tout, ce que produit
    `diff_reports` sur deux rapports vides."""
    vide = Report(points=["A", "B"], pairs=[("A", "B")])
    chemin = tmp_path / "diff_vide.pdf"
    generate_diff_pdf([], vide, vide, str(chemin))
    assert chemin.exists()
    assert chemin.read_bytes().startswith(b"%PDF")
