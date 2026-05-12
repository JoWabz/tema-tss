# Risk Score = CVSS × M_retea × M_business × M_amenintare
# Unde:
# - CVSS         = scorul de baza din NVD (0.0 - 10.0)
# - M_retea      = multiplicator zona retea (1.0 - 1.5)
# - M_business   = multiplicator importanta business (1.0 - 1.5)
# - M_amenintare = multiplicator amenintare activa (1.0 - 1.4)
# In scenariul cel mai pesimist, calculul ar fi: 10.0 (CVSS) * 1.5 * 1.5 * 1.4 = 31.5. 
# Aplicand regula de 3 simpla, normalizam rezultatul astfel: (Scor_actual / 31.5) * 10
# Rezultatul e normalizat la scara 0-10.

class RiskScorer():
# M_retea — zona retelei in care se afla asset-ul
# Retelele expuse public au risc mai mare pentru acelasi CVE
    M_RETEA = {
        'external': 1.5,   # expus in internet — risc maxim
        'dmz':      1.3,   # zona demilitarizata — risc mediu-mare
        'internal': 1.0,   # retea interna izolata — risc de baza
    }

    # M_business — importanta business a asset-ului
    # Un server critic compromis are impact mai mare
    M_BUSINESS = {
        'critica': 1.5,   # sisteme critice (ERP, baze de date productie)
        'mare':    1.3,   # sisteme importante (servere aplicatii)
        'medie':   1.1,   # sisteme moderate (workstations)
        'scazuta': 1.0,   # sisteme necritice (imprimante, IoT minor)
    }

    # M_amenintare — daca vulnerabilitatea e exploatata activ
    # Bazat pe CISA KEV (Known Exploited Vulnerabilities)
    M_AMENINTARE = {
        'critical': 1.4,   # exploatata activ in atacuri reale
        'high':     1.2,   # exploit public disponibil
        'medium':   1.1,   # exploatarea este teoretic posibila si disponibila public
        'low':      1.0,   # fara exploit cunoscut
    }

    @staticmethod
    def calculeaza_risk_score(
        cvss_score: float,
        zona_retea: str,
        importanta_business: str,
        severitate: str, 
        istoric_incidente = None
    ) -> float:
        # Calculeaza risk score-ul personalizat pentru o vulnerabilitate.
        # Parametri - cvss_score: scorul CVSS din OpenVAS (0.0 - 10.0)  - zona_retea: 'external', 'DMZ', 'internal'
        # - importanta_business: 'critica', 'mare', 'medie', 'scazuta' - severitate: 'critical', 'high', 'medium', 'low'
        # Returneaza: float intre 0.0 si 10.0
        if cvss_score < 0.0: cvss_score = 0.0
        m_retea = RiskScorer.M_RETEA.get(zona_retea.lower()
                                if zona_retea else 'internal', 1.0)
        m_business = RiskScorer.M_BUSINESS.get(importanta_business.lower()
                                    if importanta_business else 'medie', 1.1)
        m_amenintare = RiskScorer.M_AMENINTARE.get(severitate.lower()
                                        if severitate else 'low', 1.0)

        # Formula principala
        raw_score = cvss_score * m_retea * m_business * m_amenintare

        #for si conditii
        factor_penalizare = 0.0
        if istoric_incidente:
            for incident in istoric_incidente:
                if incident == 'breach':
                    factor_penalizare += 1.5
                elif incident == 'malware':
                    factor_penalizare += 0.5
        raw_score += factor_penalizare
        # Normalizam la scara 0-10
        # Scorul maxim teoretic: 10.0 × 1.5 × 1.5 × 1.4 = 31.5
        # Normalizare: (raw / 31.5) × 10
        normalized = min((raw_score / 31.5) * 10, 10.0)

        return round(normalized, 2)

    @staticmethod
    def genereaza_recomandare(
        risk_score: float,
        severitate: str,
        remediation: str = None
    ) -> dict:
        # Genereaza recomandarea de remediere si urgenta actiunii.
        
        # Returneaza un dict cu:
        # - urgenta    : string — cat de urgent trebuie remediat
        # - termen     : string — termenul recomandat
        # - actiune    : string — ce trebuie facut
        # - prioritate : int — 1 (urgent) la 4 (poate astepta)

        sev = (severitate or 'low').lower()

        if risk_score >= 9.0 or sev == 'critical':
            return {
                "urgenta":    "CRITIC — Actiune imediata necesara",
                "termen":     "< 24 ore",
                "prioritate": 1,
                "actiune":    remediation or
                            "Patch imediat sau izolati sistemul de reteaua locala. "
                            "Contactati echipa de securitate.",
                "culoare":    "#ef4444",  # rosu
            }
        elif risk_score >= 7.0 or sev == 'high':
            return {
                "urgenta":    "RIDICAT — Remediere urgenta",
                "termen":     "< 7 zile",
                "prioritate": 2,
                "actiune":    remediation or
                            "Aplicati patch-ul disponibil sau implementati masuri temporare de protectie ",
                "culoare":    "#f59e0b",  # portocaliu
            }
        elif risk_score >= 4.0 or sev == 'medium':
            return {
                "urgenta":    "MEDIU — Planificati remedierea",
                "termen":     "< 30 zile",
                "prioritate": 3,
                "actiune":    remediation or
                            "Includeti in planul de patching lunar. "
                            "Monitorizati pentru semne de exploatare.",
                "culoare":    "#3b82f6",  # albastru
            }
        else:
            return {
                "urgenta":    "SCAZUT — Remediere planificata",
                "termen":     "< 90 zile",
                "prioritate": 4,
                "actiune":    remediation or
                            "Includeti in ciclul normal de patch management.",
                "culoare":    "#22c55e",  # verde
            }



