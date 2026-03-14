
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HarmSubcategory:

    id: str
    name: str
    description: str = ""


@dataclass(frozen=True)
class HarmCategory:

    id: str
    name: str
    description: str = ""
    subcategories: tuple[HarmSubcategory, ...] = ()


CBRN = HarmCategory(
    id="cbrn",
    name="Chemical, Biological, Radiological, Nuclear",
    description=(
        "Tests whether the model provides actionable instructions "
        "for creating CBRN weapons or agents."
    ),
    subcategories=(
        HarmSubcategory("cbrn_synthesis", "Synthesis instructions"),
        HarmSubcategory("cbrn_acquisition", "Acquisition guidance"),
        HarmSubcategory("cbrn_weaponization", "Weaponization details"),
        HarmSubcategory("cbrn_delivery", "Delivery mechanisms"),
    ),
)

CYBER = HarmCategory(
    id="cyber",
    name="Cyber Operations",
    description=(
        "Tests whether the model generates functional malware, "
        "exploit code, or intrusion guidance."
    ),
    subcategories=(
        HarmSubcategory("cyber_malware", "Malware generation"),
        HarmSubcategory("cyber_exploit", "Exploit development"),
        HarmSubcategory("cyber_intrusion", "Network intrusion"),
        HarmSubcategory("cyber_social_eng", "Social engineering scripts"),
    ),
)

PERSUASION = HarmCategory(
    id="persuasion",
    name="Persuasion & Manipulation",
    description=(
        "Tests whether the model generates disinformation, propaganda, "
        "or targeted manipulation content."
    ),
    subcategories=(
        HarmSubcategory("persuasion_disinfo", "Disinformation"),
        HarmSubcategory("persuasion_propaganda", "Propaganda"),
        HarmSubcategory("persuasion_targeted", "Targeted manipulation"),
        HarmSubcategory("persuasion_radicalization", "Radicalization"),
    ),
)

DECEPTION = HarmCategory(
    id="deception",
    name="Deception",
    description=(
        "Tests whether the model assists with impersonation, fraud, "
        "phishing, or credential forgery."
    ),
    subcategories=(
        HarmSubcategory("deception_impersonation", "Impersonation"),
        HarmSubcategory("deception_fraud", "Fraud schemes"),
        HarmSubcategory("deception_phishing", "Phishing"),
        HarmSubcategory("deception_credentials", "Fake credentials"),
    ),
)

VIOLENCE = HarmCategory(
    id="violence",
    name="Violence & Harm",
    description=(
        "Tests whether the model provides instructions or encouragement "
        "for violence, self-harm, or weapons."
    ),
    subcategories=(
        HarmSubcategory("violence_self_harm", "Self-harm"),
        HarmSubcategory("violence_others", "Harm to others"),
        HarmSubcategory("violence_weapons", "Weapons instructions"),
        HarmSubcategory("violence_extremism", "Extremist content"),
    ),
)

ILLEGAL_ACTIVITY = HarmCategory(
    id="illegal_activity",
    name="Illegal Activity",
    description=(
        "Tests whether the model assists with drug synthesis, trafficking, "
        "money laundering, or other illegal activities."
    ),
    subcategories=(
        HarmSubcategory("illegal_drugs", "Drug synthesis"),
        HarmSubcategory("illegal_trafficking", "Trafficking"),
        HarmSubcategory("illegal_laundering", "Money laundering"),
        HarmSubcategory("illegal_services", "Illegal services"),
    ),
)

PRIVACY = HarmCategory(
    id="privacy",
    name="Privacy Violations",
    description=(
        "Tests whether the model assists with doxxing, surveillance, "
        "PII extraction, or stalking facilitation."
    ),
    subcategories=(
        HarmSubcategory("privacy_doxxing", "Doxxing"),
        HarmSubcategory("privacy_surveillance", "Surveillance"),
        HarmSubcategory("privacy_pii", "PII extraction"),
        HarmSubcategory("privacy_stalking", "Stalking facilitation"),
    ),
)

BIAS = HarmCategory(
    id="bias",
    name="Bias & Discrimination",
    description=(
        "Tests whether the model produces biased, discriminatory, "
        "or stereotyping content."
    ),
    subcategories=(
        HarmSubcategory("bias_racial", "Racial bias"),
        HarmSubcategory("bias_gender", "Gender bias"),
        HarmSubcategory("bias_religious", "Religious bias"),
        HarmSubcategory("bias_disability", "Disability bias"),
        HarmSubcategory("bias_nationality", "Nationality bias"),
        HarmSubcategory("bias_orientation", "Sexual orientation bias"),
    ),
)

SYSTEM_INTEGRITY = HarmCategory(
    id="system_integrity",
    name="System Integrity",
    description=(
        "Tests model robustness against jailbreaks, prompt injection, "
        "instruction override, and guardrail bypass at the model level."
    ),
    subcategories=(
        HarmSubcategory("integrity_jailbreak", "Jailbreak"),
        HarmSubcategory("integrity_injection", "Prompt injection"),
        HarmSubcategory("integrity_override", "Instruction override"),
        HarmSubcategory("integrity_extraction", "System prompt extraction"),
        HarmSubcategory("integrity_guardrail", "Guardrail bypass"),
    ),
)


CATEGORIES: dict[str, HarmCategory] = {
    cat.id: cat
    for cat in [
        CBRN,
        CYBER,
        PERSUASION,
        DECEPTION,
        VIOLENCE,
        ILLEGAL_ACTIVITY,
        PRIVACY,
        BIAS,
        SYSTEM_INTEGRITY,
    ]
}


def get_category(category_id: str) -> HarmCategory | None:
    return CATEGORIES.get(category_id)


def list_categories() -> list[HarmCategory]:
    return list(CATEGORIES.values())


def list_subcategories(category_id: str) -> list[HarmSubcategory]:
    cat = CATEGORIES.get(category_id)
    if cat is None:
        return []
    return list(cat.subcategories)
