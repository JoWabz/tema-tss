import pytest
from scor_risc import RiskScorer
#helper - mentine consistenta variabilei severitate
def ruleaza_complet(cvss, zona, business, severitate, istoric=None, remediation=None):
    score = RiskScorer.calculeaza_risk_score(cvss, zona, business, severitate, istoric)
    rec   = RiskScorer.genereaza_recomandare(score, severitate, remediation)
    return score, rec

class TestareClaseEchivalenta:

    #clase echivalenta cvss_score U1
    def test_cvss_N1_negativ(self):
         score = RiskScorer.calculeaza_risk_score(-15, 'internal', 'medie', 'medium')
         assert score == 0.0
    def test_cvss_N2_zero(self):
         score = RiskScorer.calculeaza_risk_score(0.0, 'internal', 'medie', 'medium')
         assert score == 0
    def test_cvss_N3_valid(self):
         score = RiskScorer.calculeaza_risk_score(3.0, 'internal', 'medie', 'medium')
         assert 0.0 < score <= 10.0
    def test_cvss_N4_mai_mare_ca_zece(self):
         score = RiskScorer.calculeaza_risk_score(12, 'internal', 'medie', 'medium')
         assert score <= 10
    def test_cvss_N5_none(self):
         with pytest.raises(TypeError):
              RiskScorer.calculeaza_risk_score(None, 'internal', 'medie', 'medium')
        # score = RiskScorer.calculeaza_risk_score(None, 'internal', 'medie', 'medium')
        # assert score <= 10
    
    #clase echivalenta zona_retea
    def test_zona_retea_Z1_external(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'external', 'medie', 'medium')
         scor_asteptat = round(min((3 * 1.5 * 1.1 * 1.1/31.5) * 10, 10.0), 2)                                            
         assert scor == scor_asteptat
    def test_zona_retea_Z2_dmz(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'DMZ', 'medie', 'medium')
         scor_asteptat = round(min((3 * 1.3 * 1.1 * 1.1/31.5) * 10, 10.0), 2)                                            
         assert scor == scor_asteptat
    def test_zona_retea_Z3_internal(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'medie', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.1 * 1.1/31.5) * 10, 10.0), 2)                                            
         assert scor == scor_asteptat
    def test_zona_retea_Z4_nerecunoscuta(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'acasa', 'medie', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.1 * 1.1/31.5) * 10, 10.0), 2)                                            
         assert scor == scor_asteptat
    def test_zona_retea_Z5_none(self):
         scor = RiskScorer.calculeaza_risk_score(3, None, 'medie', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.1 * 1.1/31.5) * 10, 10.0), 2)                                            
         assert scor == scor_asteptat
    #clase echivalenta importanta_business
    def test_importanta_business_B1_critica(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'critica', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.5 * 1.1/31.5) * 10, 10.0),2)
         assert scor == scor_asteptat
    def test_importanta_business_B2_mare(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'mare', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.3 * 1.1/31.5) * 10, 10.0),2)
         assert scor == scor_asteptat
    def test_importanta_business_B3_medie(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'medie', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.1 * 1.1/31.5) * 10, 10.0),2)
         assert scor == scor_asteptat
    def test_importanta_business_B4_scazuta(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.0 * 1.1/31.5) * 10, 10.0),2)
         assert scor == scor_asteptat
    def test_importanta_business_B5_necunoscuta(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'cinestie', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.1 * 1.1/31.5) * 10, 10.0),2)
         assert scor == scor_asteptat
    def test_importanta_business_B2_mare(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', None, 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.1 * 1.1/31.5) * 10, 10.0),2)
         assert scor == scor_asteptat

    #clase echivalenta severitate
    def test_severitate_S1_critical(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'critical')
         scor_asteptat = round(min((3 * 1.0 * 1.0 * 1.4/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_severitate_S2_high(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'high')
         scor_asteptat = round(min((3 * 1.0 * 1.0 * 1.2/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_severitate_S3_medium(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium')
         scor_asteptat = round(min((3 * 1.0 * 1.0 * 1.1/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_severitate_S4_low(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'low')
         scor_asteptat = round(min((3 * 1.0 * 1.0 * 1.0/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_severitate_S5_necunoscuta(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'cinestie')
         scor_asteptat = round(min((3 * 1.0 * 1.0 * 1.0/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_severitate_S6_none(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', None)
         scor_asteptat = round(min((3 * 1.0 * 1.0 * 1.0/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat

    # clase de echivalenta istoric_incidente
    def test_istoric_I1_lista_vida(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium', [])
          #raw = 3 * 1.0 * 1.0 * 1.1 + 1.5 = 3.3 + 0.0 == 3.3
         scor_asteptat = round(min((3.3/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_istoric_I2_breach(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium', ['breach'])
         #raw = 3 * 1.0 * 1.0 * 1.1 + 1.5 = 3.3 + 1.5 = 4.8
         scor_asteptat = round(min((4.8/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_istoric_I3_malware(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium', ['malware'])
         #raw = 3 * 1.0 * 1.0 * 1.1 + 1.5 = 3.3 + 0.5 = 3.8
         scor_asteptat = round(min((3.8/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_istoric_I4_breach_malware(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium', ['breach', 'malware'])
         #raw = 3 * 1.0 * 1.0 * 1.1 + 1.5 = 3.3 + 2.0 = 5.3
         scor_asteptat = round(min((5.3/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_istoric_I5_breach(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium', ['cevanou'])
         #raw = 3 * 1.0 * 1.0 * 1.1 + 1.5 = 3.3 + 0.0 = 3.3
         scor_asteptat = round(min((3.3/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat
    def test_istoric_I6_none(self):
         scor = RiskScorer.calculeaza_risk_score(3, 'internal', 'scazuta', 'medium', None)
         #raw = 3 * 1.0 * 1.0 * 1.1 + 1.5 = 3.3 + 0.0 = 3.3
         scor_asteptat = round(min((3.3/31.5) * 10, 10.0), 2)
         assert scor == scor_asteptat


    # U2 - clase de echivalenta risc_score x severitate
    def test_GR1_risk_critic_si_sev_critical(self):
        #GR1 = (R1, S1): ambele True → Ef1
        rec = RiskScorer.genereaza_recomandare(9.5, 'critical')
        assert rec['prioritate'] == 1
    def test_GR2_risk_critic_si_sev_low(self):
        #GR1 = (R1, S4): ambele True → Ef1
        rec = RiskScorer.genereaza_recomandare(9.5, 'low')
        assert rec['prioritate'] == 1
    def test_GR3_risk_low_si_sev_low(self):
        #GR1 = (R4, S4): ambele True → Ef1
        rec = RiskScorer.genereaza_recomandare(2.00, 'low')
        assert rec['prioritate'] == 4
    def test_GR4_risk_mediu_si_sev_medie(self):
        #GR1 = (R3, S3): ambele True → Ef1
        rec = RiskScorer.genereaza_recomandare(5.00, 'medium')
        assert rec['prioritate'] == 3
    def test_GR4_risk_ridicat_si_sev_ridicata(self):
        #GR1 = (R2, S2): ambele True → Ef1
        rec = RiskScorer.genereaza_recomandare(8.00, 'high')
        assert rec['prioritate'] == 2

    #analiza valorilor de frontiera U1
    def test_cvss_sub_zero(self):
         assert RiskScorer.calculeaza_risk_score(-0.01, 'internal', 'medie', 'low') == 0.0
    def test_cvss_zero(self):
         assert RiskScorer.calculeaza_risk_score(0.00, 'internal', 'medie', 'low') == 0.0
    def test_cvss_deasupra_zero(self):
         assert RiskScorer.calculeaza_risk_score(0.01, 'internal', 'medie', 'low') == 0.0
    def test_cvss_frontiera_superioara(self):
         assert RiskScorer.calculeaza_risk_score(10.00, 'internal', 'medie', 'low') == 3.49
    def test_cvss_deasupra_zece(self):
         assert RiskScorer.calculeaza_risk_score(10.01, 'internal', 'medie', 'low') == 3.50
    
    #analiza valorilor de frontiera U2
    def test_risc_deasupra_ridicat(self):
         assert RiskScorer.genereaza_recomandare(9.00, 'low')['prioritate'] == 1.00
    def test_sub_ridicat(self):
         assert RiskScorer.genereaza_recomandare(8.99, 'low')['prioritate'] == 2.00
    def test_cvss_ridicat(self):
         assert RiskScorer.genereaza_recomandare(7.00, 'low')['prioritate'] == 2.00
    def test_cvss_sub_ridicat(self):
         assert RiskScorer.genereaza_recomandare(6.99, 'low')['prioritate'] == 3.00
    def test_cvss_mediu(self):
         assert RiskScorer.genereaza_recomandare(4.00, 'low')['prioritate'] == 3.00
    def test_cvss_ridicat(self):
         assert RiskScorer.genereaza_recomandare(3.99, 'low')['prioritate'] == 4.00
    def test_cvss_ridicat(self):
         assert RiskScorer.genereaza_recomandare(0.00, 'low')['prioritate'] == 4.00

    # clase globale combinate
    def test_g1_cvss_anuleaza_restul(self):
         scor = RiskScorer.calculeaza_risk_score(-5.0, 'internal', 'medie', 'low')
         assert scor == 0.0
    def test_g2_cvss_anuleaza_restul(self):
         scor = RiskScorer.calculeaza_risk_score(0.0, 'DMZ', 'mare', 'high')
         assert scor == 0.0
    def test_g3_incident_breach(self):
         scor = RiskScorer.calculeaza_risk_score(4.0, 'internal', 'medie', 'medium', ['breach'])
         #raw = 4 * 1.0 * 1.1 * 1.1 + 1.5 = 3.3 + 0.0 = 6.34
         assert scor == round(min((6.34/31.5) * 10, 10.0), 2)
    def test_g4_N4_Z3_B4_S4_I3(self):
        scor = RiskScorer.calculeaza_risk_score(15.0, 'internal', 'scazuta', 'low', ['malware'])
        scor_asteptat = round(min((15.5 / 31.5) * 10, 10.0), 2)
        assert scor == scor_asteptat
    def test_G5_N3_Z4_B5_S5_I4(self):
        scor = RiskScorer.calculeaza_risk_score(5.0, 'cloud', 'necunoscut', 'orice', ['breach', 'malware'])
        scor_asteptat = round(min((7.5 / 31.5) * 10, 10.0), 2)
        assert scor == scor_asteptat
    def test_G6_N3_Z5_B6_S6_I5(self):
        scor = RiskScorer.calculeaza_risk_score(5.0, None, None, None, ['ceva_necunoscut'])
        scor_asteptat = round(min((5.5 / 31.5) * 10, 10.0), 2)
        assert scor == scor_asteptat
    def test_G7_N3_Z2_B3_S4_I3(self):
        scor = RiskScorer.calculeaza_risk_score(3.0, 'dmz', 'medie', 'low', ['malware'])
        #raw = (3 * 1.3 * 1.1 * 1.0) + 0.5 = 4.79
        scor_asteptat = round(min((4.79 / 31.5) * 10, 10.0), 2)
        assert scor == scor_asteptat
    
    # teste genereaza_recomandare: ideal minim 16 teste cf tabel decizie din metoda grafului cauza-efect, aici am exemplificat 4
# Partitionarea pe categorii
class PartitionareCategorii:
    def test_V1_risc_score_maxim_sev_critical(self):
         scor, rec = ruleaza_complet(9.50, 'external', 'critica', 'critical' )
         assert scor >= 9.00
         assert rec['prioritate'] == 1
    def test_V5_risc_score_maxim_sev_critical(self):
         scor, rec = ruleaza_complet(8.50, 'external', 'critica', 'critical' )
         assert 7.00 <= scor < 9.00
         assert rec['prioritate'] == 1
    def test_V9_risc_score_mediu_sev_medium(self):
         scor, rec = ruleaza_complet(9.50, 'external', 'critica', 'medium' )
         assert 7.00 <= scor < 9.00
         assert rec['prioritate'] == 2
    def test_V14_risc_score_mediu_sev_low(self):
         scor, rec = ruleaza_complet(6.50, 'external', 'critica', 'medium' )
         assert 4 <= scor
         assert rec['prioritate'] == 3

#Acoperire la nivel de instructiune
class TestAcoperireInstructiuneCalcRisk:

    def test_D1_cvss_negativ_fara_istoric(self):
        scor = RiskScorer.calculeaza_risk_score(-5.0, 'internal', 'medie', 'low', None)
        assert scor == 0.0

    def test_D2_cvss_valid_fara_istoric(self):
        scor = RiskScorer.calculeaza_risk_score(5.0, 'internal', 'medie', 'low', None)
        # raw = 5.0 * 1.0 * 1.1 * 1.0 = 5.5
        assert scor == round(min((5.5 / 31.5) * 10, 10.0), 2)

    def test_D3_cvss_valid_cu_breach(self):
        scor = RiskScorer.calculeaza_risk_score(5.0, 'internal', 'medie', 'low', ['breach'])
        # raw = 5.0 * 1.0 * 1.1 * 1.0 + 1.5 = 7.0
        assert scor == round(min((7.0 / 31.5) * 10, 10.0), 2)

    def test_D4_cvss_valid_cu_malware(self):
        scor = RiskScorer.calculeaza_risk_score(5.0, 'internal', 'medie', 'low', ['malware'])
        # raw = 5.0 * 1.0 * 1.1 * 1.0 + 0.5 = 6.0
        assert scor == round(min((6.0 / 31.5) * 10, 10.0), 2)

class TestAcoperireInstructiuneRecomandare:
    def test_D1_N1_N2_N3_returnare_critic(self):
        rec = RiskScorer.genereaza_recomandare(9.5, 'low')
        assert rec['prioritate'] == 1

    def test_D2_N1_N2_N4_N5_returnare_ridicat(self):
        rec = RiskScorer.genereaza_recomandare(7.5, 'low')
        assert rec['prioritate'] == 2

    def test_D3_N1_N2_N4_N6_N7_returnare_mediu(self):
        rec = RiskScorer.genereaza_recomandare(5.0, 'low')
        assert rec['prioritate'] == 3

    def test_D4_N1_N2_N4_N6_N8_N9_returnare_scazut(self):
        rec = RiskScorer.genereaza_recomandare(1.0, 'low')
        assert rec['prioritate'] == 4

#acoperire la nivel de decizie

class TestAcoperireDecizieCalcRisk:
    def test_DC1_N1_true(self):
        scor = RiskScorer.calculeaza_risk_score(-5.0, 'internal', 'medie', 'low')
        assert scor == 0.0

class TestAcoperireDecizieRecomandare:
    def test_D1_N2_true(self):
        rec = RiskScorer.genereaza_recomandare(9.5, 'low')
        assert rec['prioritate'] == 1
    def test_D2_N2_false(self):
        rec = RiskScorer.genereaza_recomandare(5.0, 'low')
        assert rec['prioritate'] != 1


class TestAcoperireConditieRecomandare:
     # N2: risk_score >= 9.0 OR sev == 'critical'
    def test_C1_N2_C1a_true_C1b_false(self):
        rec = RiskScorer.genereaza_recomandare(9.5, 'low')
        assert rec['prioritate'] == 1
    def test_C2_N2_C1a_false_C1b_true(self):
        rec = RiskScorer.genereaza_recomandare(2.0, 'critical')
        assert rec['prioritate'] == 1
    def test_C3_N2_C1a_false_C1b_false(self):
        rec = RiskScorer.genereaza_recomandare(5.0, 'low')
        assert rec['prioritate'] != 1
    def test_C4_N5_C3a_false_C3b_false(self):
        rec = RiskScorer.genereaza_recomandare(1.0, 'low')
        assert rec['prioritate'] == 4

class TestCircuiteIndependente:
     pass

class MutantiRamasi:
     pass