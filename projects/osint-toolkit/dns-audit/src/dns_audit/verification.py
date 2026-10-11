"""Rozpoznawanie rekordow TXT weryfikujacych wlasnosc domeny przez uslugi zewnetrzne."""

from __future__ import annotations

import re
from dataclasses import dataclass

# (wzorzec dopasowany od poczatku rekordu, usluga, kategoria)
_RULES: list[tuple[str, str, str]] = [
    (r"google-site-verification=", "Google (Search Console / Workspace)", "wyszukiwarki i Google"),
    (r"google-gws-recovery-domain-verification=", "Google Workspace (odzyskiwanie konta)", "poczta i biuro"),
    (r"MS=", "Microsoft 365 / Entra ID", "poczta i biuro"),
    (r"ms-domain-verification=", "Microsoft (Power Platform / Dynamics)", "poczta i biuro"),
    (r"facebook-domain-verification=", "Meta (Facebook / Instagram Business)", "marketing i reklama"),
    (r"atlassian-domain-verification=", "Atlassian (Jira / Confluence / Cloud)", "narzedzia zespolowe"),
    (r"atlassian-sending-domain-verification=", "Atlassian (wysylka e-mail)", "narzedzia zespolowe"),
    (r"apple-domain-verification=", "Apple (Business / School Manager, Sign in with Apple)", "poczta i biuro"),
    (r"apple-domain=", "Apple (Business Connect)", "poczta i biuro"),
    (r"docusign=", "DocuSign", "narzedzia zespolowe"),
    (r"adobe-idp-site-verification=", "Adobe (Admin Console / Creative Cloud)", "narzedzia zespolowe"),
    (r"adobe-sign-verification=", "Adobe Sign", "narzedzia zespolowe"),
    (r"stripe-verification=", "Stripe (platnosci)", "platnosci i e-commerce"),
    (r"zoom-domain-verification=", "Zoom", "narzedzia zespolowe"),
    (r"ZOOM_verify_", "Zoom", "narzedzia zespolowe"),
    (r"globalsign-smime-dv=", "GlobalSign (certyfikaty S/MIME)", "certyfikaty i PKI"),
    (r"globalsign-domain-verification=", "GlobalSign (certyfikaty)", "certyfikaty i PKI"),
    (r"_?acme-challenge", "ACME (certyfikaty, np. Let's Encrypt)", "certyfikaty i PKI"),
    (r"onetrust-domain-verification=", "OneTrust (zgody, cookies)", "zgodnosc i prywatnosc"),
    (r"miro-verification=", "Miro", "narzedzia zespolowe"),
    (r"have-i-been-pwned-verification=", "Have I Been Pwned (monitoring domeny)", "bezpieczenstwo"),
    (r"cisco-ci-domain-verification=", "Cisco (Webex / Umbrella / Secure Email)", "bezpieczenstwo"),
    (r"webexdomainverification", "Cisco Webex", "narzedzia zespolowe"),
    (r"dropbox-domain-verification=", "Dropbox", "narzedzia zespolowe"),
    (r"slack-domain-verification=", "Slack", "narzedzia zespolowe"),
    (r"pinterest-site-verification=", "Pinterest", "marketing i reklama"),
    (r"yandex-verification", "Yandex (Webmaster)", "wyszukiwarki i Google"),
    (r"baidu-site-verification=", "Baidu", "wyszukiwarki i Google"),
    (r"openai-domain-verification=", "OpenAI", "narzedzia zespolowe"),
    (r"anthropic-domain-verification", "Anthropic", "narzedzia zespolowe"),
    (r"docker-verification=", "Docker Hub", "narzedzia deweloperskie"),
    (r"mongodb-site-verification=", "MongoDB Atlas", "narzedzia deweloperskie"),
    (r"twilio-domain-verification=", "Twilio", "narzedzia deweloperskie"),
    (r"postman-domain-verification=", "Postman", "narzedzia deweloperskie"),
    (r"github-verification=", "GitHub", "narzedzia deweloperskie"),
    (r"gitlab-verification", "GitLab", "narzedzia deweloperskie"),
    (r"heroku-domain-verification=", "Heroku", "narzedzia deweloperskie"),
    (r"dynatrace-site-verification=", "Dynatrace", "narzedzia deweloperskie"),
    (r"cloudflare-verify=", "Cloudflare", "narzedzia deweloperskie"),
    (r"calendly-site-verification=", "Calendly", "narzedzia zespolowe"),
    (r"canva-site-verification=", "Canva", "narzedzia zespolowe"),
    (r"notion-domain-verification=", "Notion", "narzedzia zespolowe"),
    (r"asana-verification=", "Asana", "narzedzia zespolowe"),
    (r"wrike-verification=", "Wrike", "narzedzia zespolowe"),
    (r"smartsheet-site-validation=", "Smartsheet", "narzedzia zespolowe"),
    (r"citrix-verification-code=", "Citrix", "narzedzia zespolowe"),
    (r"logmein-verification-code=", "LogMeIn / GoTo", "narzedzia zespolowe"),
    (r"teamviewer-sso-verification=", "TeamViewer", "narzedzia zespolowe"),
    (r"knowbe4-site-verification=", "KnowBe4 (szkolenia phishingowe)", "bezpieczenstwo"),
    (r"bugcrowd-verification=", "Bugcrowd", "bezpieczenstwo"),
    (r"norton-safeweb-site-verification=", "Norton Safe Web", "bezpieczenstwo"),
    (r"status-page-domain-verification=", "Atlassian Statuspage", "narzedzia zespolowe"),
    (r"zapier-domain-verification-challenge=", "Zapier", "narzedzia zespolowe"),
    (r"ahrefs-site-verification_", "Ahrefs (SEO)", "marketing i reklama"),
    (r"tiktok-domain-verification=", "TikTok", "marketing i reklama"),
    (r"sendinblue-code:", "Brevo (Sendinblue)", "poczta masowa"),
    (r"brevo-code:", "Brevo", "poczta masowa"),
    (r"mandrill_verify\.", "Mandrill (Mailchimp Transactional)", "poczta masowa"),
    (r"protonmail-verification=", "Proton Mail", "poczta i biuro"),
    (r"zoho-verification=", "Zoho", "poczta i biuro"),
    (r"forward-email", "Forward Email", "poczta i biuro"),
    (r"amazonses:", "Amazon SES", "poczta masowa"),
    (r"ketch-verification", "Ketch (zgody)", "zgodnosc i prywatnosc"),
    (r"loaderio=", "Loader.io (testy obciazenia)", "narzedzia deweloperskie"),
    (r"workplace-domain-verification=", "Meta Workplace", "narzedzia zespolowe"),
    (r"shopify-verification-code=", "Shopify", "platnosci i e-commerce"),
    (r"paypal-?site-?verification", "PayPal", "platnosci i e-commerce"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE), svc, cat) for p, svc, cat in _RULES]


@dataclass(frozen=True)
class Verification:
    service: str
    category: str
    record: str


def detect_verification(txt: str) -> Verification | None:
    t = txt.strip()
    for rx, service, category in _COMPILED:
        if rx.match(t):
            return Verification(service, category, t)
    return None


def detect_verifications(txts: list[str] | tuple[str, ...]) -> list[Verification]:
    out: list[Verification] = []
    for t in txts:
        v = detect_verification(t)
        if v:
            out.append(v)
    return out


_EMAIL_AUTH_PREFIXES = ("v=spf1", "v=dmarc1", "v=dkim1", "v=stsv1", "v=tlsrptv1", "v=bimi1")


def is_email_auth(txt: str) -> bool:
    return txt.strip().lower().startswith(_EMAIL_AUTH_PREFIXES)
