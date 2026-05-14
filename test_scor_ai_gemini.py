import pytest
from scor_risc import RiskScorer

# =================================================================
# 1. TESTE PENTRU calculeaza_risk_score (Partiționare, Frontiere, Decizii)
# =================================================================

class TestCalculeazaRiskScore:

    # --- Testare Clase de Echivalență și Valori de Frontieră (Intrări) ---
    @pytest.mark.parametrize("cvss, zona, business, severitate, expected_range", [
        (0.0, 'internal', 'scazuta', 'low', (0.0, 0.5)),      # Minim absolut
        (10.0, 'external', 'critica', 'critical', (9.5, 10.0)), # Maxim absolut
        (5.0, 'dmz', 'mare', 'high', (4.0, 7.0)),             # Valori medii
        (-1.0, 'internal', 'medie', 'low', (0.0, 1.0)),       # Intrare invalidă (negativă)
    ])
    def test_equivalence_partitioning_inputs(self, cvss, zona, business, severitate, expected_range):
        score = RiskScorer.calculeaza_risk_score(cvss, zona, business, severitate)
        assert expected_range[0] <= score <= expected_range[1]

    # --- Testare Acoperire la nivel de Instrucțiune și Decizie (Multiplicatori) ---
    def test_multipliers_and_branch_coverage(self):
        # Testăm dacă ramura 'if not zona_retea' funcționează (default internal 1.0)
        score_default = RiskScorer.calculeaza_risk_score(10.0, None, None, None)
        # 10.0 * 1.0 (internal) * 1.1 (default business medie) * 1.0 (low threat) = 11.0
        # Normalizat: (11.0 / 31.5) * 10 = 3.49
        assert score_default == 3.49

    # --- Analiza Valorilor de Frontieră (Domeniul de Ieșiri: 0.0 - 10.0) ---
    def test_output_boundary_max(self):
        # Forțăm un scor peste maxim pentru a testa min(..., 10.0)
        # CVSS 10 + Breach (1.5) + Multiplicatori maximi
        score = RiskScorer.calculeaza_risk_score(10.0, 'external', 'critica', 'critical', ['breach', 'breach'])
        assert score == 10.0  # Nu trebuie să depășească 10

    # --- Testare Condiții și Buclă (Istoric Incidente) ---
    def test_condition_and_loop_coverage_incidents(self):
        # Acoperim bucla 'for incident in istoric_incidente' și condițiile 'if/elif'
        istoric = ['breach', 'malware', 'unknown']
        # Penalizare: 1.5 (breach) + 0.5 (malware) + 0.0 (unknown) = 2.0
        # CVSS 5.0 * 1.0 * 1.0 * 1.0 = 5.0 + 2.0 = 7.0
        # Normalizat: (7.0 / 31.5) * 10 = 2.22
        score = RiskScorer.calculeaza_risk_score(5.0, 'internal', 'scazuta', 'low', istoric)
        assert score == 2.22

# =================================================================
# 2. TESTE PENTRU genereaza_recomandare (Decizii și Priorități)
# =================================================================

class TestGenereazaRecomandare:

    # --- Acoperire la nivel de Decizie (Toate ramurile if/elif/else) ---
    @pytest.mark.parametrize("score, sev, expected_urgency, expected_pri", [
        (9.5, 'low', "CRITIC", 1),      # Scat scor critic
        (2.0, 'critical', "CRITIC", 1), # Scos mic, dar severitate critică (Condiție OR)
        (7.5, 'medium', "RIDICAT", 2),  # Ramura High
        (5.0, 'low', "MEDIU", 3),       # Ramura Medium
        (2.0, 'low', "SCAZUT", 4),      # Ramura Low (else)
    ])
    def test_decision_coverage_recommendations(self, score, sev, expected_urgency, expected_pri):
        rec = RiskScorer.genereaza_recomandare(score, sev)
        assert expected_urgency in rec["urgenta"]
        assert rec["prioritate"] == expected_pri

    def test_custom_remediation_text(self):
        # Verificăm dacă textul personalizat de remediere este returnat corect
        custom_text = "Update Apache to v2.4.50"
        rec = RiskScorer.genereaza_recomandare(8.0, 'high', custom_text)
        assert rec["actiune"] == custom_text

# =================================================================
# 3. TESTARE PENTRU MUTANȚI (Exemple de scenarii)
# =================================================================

def test_mutation_score_rounding():
    """
    Previne mutanții care ar schimba precizia (ex: eliminarea round()).
    """
    score = RiskScorer.calculeaza_risk_score(7.33, 'internal', 'medie', 'low')
    # Rezultatul brut 7.33 * 1 * 1.1 * 1 = 8.063 -> (8.063/31.5)*10 = 2.559...
    # Rotunjit trebuie să fie 2.56
    assert score == 2.56

def test_mutation_case_sensitivity():
    """
    Previne mutanții care ar elimina .lower(), asigurând robustețea datelor.
    """
    score_upper = RiskScorer.calculeaza_risk_score(10.0, 'EXTERNAL', 'CRITICA', 'CRITICAL')
    score_lower = RiskScorer.calculeaza_risk_score(10.0, 'external', 'critica', 'critical')
    assert score_upper == score_lower