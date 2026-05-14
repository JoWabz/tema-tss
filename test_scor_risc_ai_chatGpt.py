"""
Suită de teste pytest pentru RiskScorer din scor_risc.py.

Strategii acoperite:
- partiționare în clase de echivalență pentru intrări valide, lipsă/None, necunoscute și istoric incidente;
- partiționare pe domeniul de ieșiri pentru recomandări: CRITIC, RIDICAT, MEDIU, SCAZUT;
- analiza valorilor de frontieră pentru pragurile 4.0, 7.0, 9.0 și pentru CVSS 0/10;
- acoperire la nivel de instrucțiune, decizie și condiție;
- teste orientate pe mutanți: schimbări de operatori >=, modificări de multiplicatori, eliminarea lower(),
  eliminarea clamp/min/round, schimbarea valorilor de penalizare sau a fallback-urilor implicite.
"""

import pytest

from scor_risc import RiskScorer


def expected_score(cvss, m_retea, m_business, m_amenintare, penalizare=0.0):
    """Oracol explicit pentru formulă, păstrat separat de implementare."""
    if cvss < 0.0:
        cvss = 0.0
    raw = cvss * m_retea * m_business * m_amenintare + penalizare
    return round(min((raw / 31.5) * 10, 10.0), 2)


# ---------------------------------------------------------------------------
# calculeaza_risk_score
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "cvss,zona,business,severitate,istoric,expected",
    [
        # Clasă echivalență: risc minim / CVSS zero
        (0.0, "internal", "scazuta", "low", None, 0.00),

        # Clasă echivalență: valori valide nominale, fără incidente
        (5.0, "internal", "medie", "medium", None, expected_score(5.0, 1.0, 1.1, 1.1)),

        # Clasă echivalență: risc maxim teoretic, verifică și plafonarea la 10
        (10.0, "external", "critica", "critical", None, 10.00),

        # Clasă echivalență: zonă DMZ și business mare
        (7.5, "dmz", "mare", "high", None, expected_score(7.5, 1.3, 1.3, 1.2)),
    ],
)
def test_calculeaza_risk_score_clase_echivalenta_valide(
    cvss, zona, business, severitate, istoric, expected
):
    assert RiskScorer.calculeaza_risk_score(
        cvss, zona, business, severitate, istoric
    ) == expected


@pytest.mark.parametrize(
    "cvss,zona,business,severitate,expected",
    [
        # Frontiera inferioară: sub 0 trebuie mapat la 0
        (-0.01, "external", "critica", "critical", 0.00),

        # Frontiera inferioară exactă: 0 rămâne 0
        (0.0, "external", "critica", "critical", 0.00),

        # Frontiera superioară normală: 10 cu multiplicatori minimi nu este plafonat
        (10.0, "internal", "scazuta", "low", expected_score(10.0, 1.0, 1.0, 1.0)),

        # Peste maximul CVSS documentat: implementarea nu limitează CVSS la 10,
        # dar limitează scorul normalizat la 10.
        (20.0, "external", "critica", "critical", 10.00),
    ],
)
def test_calculeaza_risk_score_valori_frontiera_cvss(
    cvss, zona, business, severitate, expected
):
    assert RiskScorer.calculeaza_risk_score(cvss, zona, business, severitate) == expected


def test_calculeaza_risk_score_accepta_litere_mari_si_mici():
    # Mutant killer: eliminarea apelului .lower() ar schimba rezultatul.
    assert RiskScorer.calculeaza_risk_score("5.0" if False else 5.0, "DMZ", "MARE", "HIGH") == expected_score(
        5.0, 1.3, 1.3, 1.2
    )


@pytest.mark.parametrize(
    "zona,business,severitate,expected",
    [
        # None activează valorile implicite: internal, medie, low
        (None, None, None, expected_score(6.0, 1.0, 1.1, 1.0)),

        # Chei necunoscute folosesc fallback-ul .get(...): 1.0, 1.1, 1.0
        ("unknown-zone", "unknown-business", "unknown-severity", expected_score(6.0, 1.0, 1.1, 1.0)),

        # Șir gol este falsy și intră pe valorile implicite din expresia condițională
        ("", "", "", expected_score(6.0, 1.0, 1.1, 1.0)),
    ],
)
def test_calculeaza_risk_score_intrari_lipsa_sau_necunoscute(
    zona, business, severitate, expected
):
    assert RiskScorer.calculeaza_risk_score(6.0, zona, business, severitate) == expected


@pytest.mark.parametrize(
    "istoric,penalizare",
    [
        (None, 0.0),                 # decizie if istoric_incidente = False
        ([], 0.0),                   # listă goală = False
        (["other"], 0.0),            # parcurgere for fără ramuri breach/malware
        (["breach"], 1.5),           # ramura if incident == breach
        (["malware"], 0.5),          # ramura elif incident == malware
        (["breach", "malware", "ignored"], 2.0),
    ],
)
def test_calculeaza_risk_score_istoric_incidente_acoperire_decizie_si_instructiune(
    istoric, penalizare
):
    assert RiskScorer.calculeaza_risk_score(
        5.0, "internal", "scazuta", "low", istoric
    ) == expected_score(5.0, 1.0, 1.0, 1.0, penalizare)


def test_calculeaza_risk_score_rotunjeste_la_doua_zecimale():
    # Mutant killer: eliminarea round(..., 2) sau schimbarea preciziei este detectată.
    rezultat = RiskScorer.calculeaza_risk_score(5.0, "internal", "medie", "medium")
    assert rezultat == 1.92
    assert isinstance(rezultat, float)


def test_calculeaza_risk_score_plafoneaza_la_10_dupa_penalizari():
    # Mutant killer: eliminarea min(..., 10.0) ar produce un scor > 10.
    rezultat = RiskScorer.calculeaza_risk_score(
        10.0, "external", "critica", "critical", ["breach", "malware"]
    )
    assert rezultat == 10.00


# ---------------------------------------------------------------------------
# genereaza_recomandare
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "risk_score,severitate,expected_prioritate,expected_termen,expected_prefix,expected_culoare",
    [
        # Domeniu de ieșire: SCAZUT
        (0.0, "low", 4, "< 90 zile", "SCAZUT", "#51e086"),
        (3.99, "low", 4, "< 90 zile", "SCAZUT", "#51e086"),

        # Frontieră 4.0: MEDIU
        (4.0, "low", 3, "< 30 zile", "MEDIU", "#0b34e9"),
        (6.99, "low", 3, "< 30 zile", "MEDIU", "#0b34e9"),

        # Frontieră 7.0: RIDICAT
        (7.0, "low", 2, "< 7 zile", "RIDICAT", "#e2b870"),
        (8.99, "low", 2, "< 7 zile", "RIDICAT", "#e2b870"),

        # Frontieră 9.0: CRITIC
        (9.0, "low", 1, "< 24 ore", "CRITIC", "#e41b1b"),
        (10.0, "low", 1, "< 24 ore", "CRITIC", "#e41b1b"),
    ],
)
def test_genereaza_recomandare_partitii_iesire_si_frontiere_scor(
    risk_score,
    severitate,
    expected_prioritate,
    expected_termen,
    expected_prefix,
    expected_culoare,
):
    recomandare = RiskScorer.genereaza_recomandare(risk_score, severitate)

    assert recomandare["prioritate"] == expected_prioritate
    assert recomandare["termen"] == expected_termen
    assert recomandare["urgenta"].startswith(expected_prefix)
    assert recomandare["culoare"] == expected_culoare
    assert isinstance(recomandare["actiune"], str)
    assert recomandare["actiune"]


@pytest.mark.parametrize(
    "risk_score,severitate,expected_prioritate",
    [
        # Acoperire condiție: risk_score >= 9 False, sev == critical True
        (1.0, "critical", 1),

        # risk_score >= 7 False, sev == high True
        (1.0, "high", 2),

        # risk_score >= 4 False, sev == medium True
        (1.0, "medium", 3),

        # toate condițiile pe severitate False; decide doar scorul
        (1.0, "low", 4),
    ],
)
def test_genereaza_recomandare_severitatea_poate_suprascrie_scorul(
    risk_score, severitate, expected_prioritate
):
    assert RiskScorer.genereaza_recomandare(risk_score, severitate)["prioritate"] == expected_prioritate


@pytest.mark.parametrize(
    "risk_score,severitate,expected_prioritate",
    [
        # Acoperire condiție pentru partea stângă a fiecărui OR
        (9.5, "low", 1),
        (7.5, "low", 2),
        (4.5, "low", 3),
    ],
)
def test_genereaza_recomandare_scorul_poate_determina_prioritatea(
    risk_score, severitate, expected_prioritate
):
    assert RiskScorer.genereaza_recomandare(risk_score, severitate)["prioritate"] == expected_prioritate


def test_genereaza_recomandare_severitate_none_devine_low():
    # Mutant killer: schimbarea fallback-ului severitate or 'low'.
    assert RiskScorer.genereaza_recomandare(3.0, None)["prioritate"] == 4


def test_genereaza_recomandare_accepta_severitate_case_insensitive():
    # Mutant killer: eliminarea lower().
    assert RiskScorer.genereaza_recomandare(1.0, "CRITICAL")["prioritate"] == 1
    assert RiskScorer.genereaza_recomandare(1.0, "HIGH")["prioritate"] == 2
    assert RiskScorer.genereaza_recomandare(1.0, "MEDIUM")["prioritate"] == 3


def test_genereaza_recomandare_foloseste_remediation_custom():
    actiune = "Aplică patch-ul KB-123 și repornește serviciul."
    recomandare = RiskScorer.genereaza_recomandare(8.0, "low", remediation=actiune)

    assert recomandare["prioritate"] == 2
    assert recomandare["actiune"] == actiune


@pytest.mark.parametrize(
    "risk_score,severitate,fragment_default",
    [
        (9.0, "low", "Efectuati un patch imediat"),
        (7.0, "low", "Aplicati patch-ul disponibil"),
        (4.0, "low", "Includeti in planul de patch lunar"),
        (3.0, "low", "Includeti in planul normal"),
    ],
)
def test_genereaza_recomandare_foloseste_actiune_default_cand_remediation_lipseste(
    risk_score, severitate, fragment_default
):
    recomandare = RiskScorer.genereaza_recomandare(risk_score, severitate, remediation=None)
    assert fragment_default in recomandare["actiune"]


def test_flux_integrare_score_plus_recomandare_critic():
    # Test de integrare mic: un scor calculat maxim trebuie să ducă la recomandare critică.
    score = RiskScorer.calculeaza_risk_score(10.0, "external", "critica", "critical")
    recomandare = RiskScorer.genereaza_recomandare(score, "critical")

    assert score == 10.0
    assert recomandare["prioritate"] == 1
    assert recomandare["termen"] == "< 24 ore"
