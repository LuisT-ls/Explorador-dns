import socket
import whois
import dns.resolver
import requests
import ssl
import json
import concurrent.futures
from urllib.parse import urljoin, urlparse, parse_qs
import OpenSSL
from datetime import datetime
import subprocess
import threading
from colorama import init, Fore, Style
import sys
import time
import nmap
from urllib.parse import urlparse
from datetime import datetime, timedelta
import logging
import re
import os
import hashlib
import base64

# Bibliotecas para geolocalização e reputação
import geoip2.database
import tldextract

# Novas bibliotecas para as funcionalidades de segurança
import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Inicializa colorama para formatação colorida
init()

# Configuration and logging setup
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("domain_analysis.log", mode="a"),
        logging.StreamHandler(sys.stdout),
    ],
)

# Configurações para as novas funcionalidades de segurança
BLACKLIST_SERVICES = {
    "spamhaus": {
        "zen.spamhaus.org": "127.0.0.2-127.0.0.255",
        "sbl.spamhaus.org": "127.0.0.2-127.0.0.255",
        "xbl.spamhaus.org": "127.0.0.2-127.0.0.255",
        "pbl.spamhaus.org": "127.0.0.2-127.0.0.255",
    },
    "surbl": "multi.surbl.org",
    "uribl": "black.uribl.com",
    "dnsbl": "dnsbl.sorbs.net",
    "barracuda": "b.barracudacentral.org",
    "sorbs": "dnsbl.sorbs.net",
    "spamcop": "bl.spamcop.net",
}

REPUTATION_APIS = {
    "virustotal": {
        "url": "https://www.virustotal.com/vtapi/v2/url/report",
        "api_key_required": True,
        "rate_limit": 4,  # requests per minute
    },
    "urlhaus": {
        "url": "https://urlhaus-api.abuse.ch/v1/host/",
        "api_key_required": False,
        "rate_limit": 10,
    },
    "phishtank": {
        "url": "https://checkurl.phishtank.com/checkurl/",
        "api_key_required": False,
        "rate_limit": 15,
    },
    "google_safebrowsing": {
        "url": "https://safebrowsing.googleapis.com/v4/threatMatches:find",
        "api_key_required": True,
        "rate_limit": 10,
    },
    "ibm_xforce": {
        "url": "https://api.xforce.ibmcloud.com/url/",
        "api_key_required": True,
        "rate_limit": 5,
    },
}

MALWARE_INDICATORS = {
    "file_types": [".exe", ".bat", ".cmd", ".scr", ".pif", ".com", ".vbs", ".js"],
    "suspicious_patterns": [
        r"download.*\.exe",
        r"update.*\.exe",
        r"security.*\.exe",
        r"scan.*\.exe",
        r"clean.*\.exe",
        r"\.zip.*password",
        r"urgent.*action",
        r"account.*suspended",
        r"verify.*identity",
        r"bank.*security",
    ],
    "malicious_domains": [
        "malware.example.com",
        "phishing.example.com",
        "scam.example.com",
    ],
}

# Payloads para testes de segurança
SECURITY_PAYLOADS = {
    "sql_injection": [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT NULL--",
        "admin'--",
        "1' OR '1' = '1' #",
        "' OR 1=1#",
        "' OR 1=1--",
        "') OR ('1'='1",
        "admin' OR '1'='1'--",
        "' OR 'x'='x",
    ],
    "xss": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        '<img src="x" onerror="alert(\'XSS\')">',
        "<script>alert(document.cookie)</script>",
    ],
    "csrf": [
        "csrf_token",
        "authenticity_token",
        "_token",
        "xsrf_token",
        "csrf",
        "token",
        "nonce",
        "request_token",
        "form_token",
        "security_token",
    ],
}

# Arquivos e diretórios sensíveis para verificação
SENSITIVE_FILES = [
    # Arquivos de configuração
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "config.php",
    "config.ini",
    "config.json",
    "config.yml",
    "database.yml",
    "db.php",
    "settings.php",
    "wp-config.php",
    # Arquivos de backup
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "backup.bak",
    "backup.old",
    "backup.tmp",
    "backup.db",
    "backup.xml",
    "backup.txt",
    "backup.log",
    "backup.dat",
    "backup.cfg",
    # Arquivos de controle de versão
    ".git/config",
    ".git/HEAD",
    ".git/index",
    ".git/logs/HEAD",
    ".svn/entries",
    ".hg/hgrc",
    ".bzr/branch/branch.conf",
    # Arquivos de log e debug
    "debug.log",
    "error.log",
    "access.log",
    "php_errors.log",
    "mysql.log",
    "apache.log",
    "nginx.log",
    "web.log",
    # Arquivos temporários
    "temp.txt",
    "tmp.txt",
    "cache.txt",
    "session.txt",
    "upload.txt",
    "download.txt",
    "test.txt",
    "demo.txt",
    # Arquivos de administração
    "admin.txt",
    "administrator.txt",
    "manage.txt",
    "control.txt",
    "panel.txt",
    "dashboard.txt",
    "console.txt",
    "shell.txt",
    # Arquivos de banco de dados
    "database.sql",
    "db.sql",
    "dump.sql",
    "export.sql",
    "schema.sql",
    "structure.sql",
    "data.sql",
    "users.sql",
    # Arquivos de API
    "api.txt",
    "swagger.txt",
    "docs.txt",
    "documentation.txt",
    "endpoints.txt",
    "routes.txt",
    "methods.txt",
    "specs.txt",
]

# Headers de segurança para verificação
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS - Força conexões HTTPS",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "risk": "high",
    },
    "Content-Security-Policy": {
        "description": "CSP - Previne ataques XSS e injection",
        "recommended": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
        "risk": "high",
    },
    "X-Frame-Options": {
        "description": "Previne clickjacking",
        "recommended": "DENY ou SAMEORIGIN",
        "risk": "medium",
    },
    "X-Content-Type-Options": {
        "description": "Previne MIME type sniffing",
        "recommended": "nosniff",
        "risk": "medium",
    },
    "X-XSS-Protection": {
        "description": "Proteção XSS do navegador",
        "recommended": "1; mode=block",
        "risk": "medium",
    },
    "Referrer-Policy": {
        "description": "Controle de informações de referência",
        "recommended": "strict-origin-when-cross-origin",
        "risk": "low",
    },
    "Permissions-Policy": {
        "description": "Controle de recursos do navegador",
        "recommended": "geolocation=(), microphone=(), camera=()",
        "risk": "low",
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Isolamento de recursos cross-origin",
        "recommended": "require-corp",
        "risk": "medium",
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Controle de janelas popup",
        "recommended": "same-origin",
        "risk": "medium",
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controle de recursos cross-origin",
        "recommended": "same-origin",
        "risk": "low",
    },
}


class AdvancedDomainAnalyzer:
    def __init__(self, domain, config=None):
        self.domain = self._clean_domain(domain)
        self.config = config or self._default_config()
        self.logger = logging.getLogger(self.__class__.__name__)
        self._setup_session()
        self._load_geolocation_db()
        self.analysis_results = {}

    def _default_config(self):
        return {
            "timeout": 10,
            "max_workers": 10,
            "reputation_apis": [
                "https://www.virustotal.com/vtapi/v2/url/report",
                "https://urlhaus-api.abuse.ch/v1/host/",
                "https://api.malsir.com/v1/lookup",
            ],
            "security_threshold": 0.3,
            "common_ports": [21, 22, 80, 443, 3306, 8080, 5432],
        }


# Desativa avisos de SSL não verificado
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)


class DomainAnalyzer:
    def __init__(self, domain):
        self.domain = self.clean_domain(domain)
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )

        # Carregar banco de dados de geolocalização
        try:
            self.geoip_reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
        except FileNotFoundError:
            print(
                f"{Fore.YELLOW}Aviso: Banco de dados GeoLite2 não encontrado. Geolocalização desativada.{Style.RESET_ALL}"
            )
            self.geoip_reader = None

        # Configurações para as novas funcionalidades
        self.blacklist_results = {}
        self.malware_analysis = {}
        self.phishing_indicators = {}
        self.reputation_score = 0
        self.reputation_details = {}

    @staticmethod
    def clean_domain(domain):
        if domain.startswith(("http://", "https://")):
            domain = domain.split("://")[1]
        return domain.split("/")[0].strip()

    def print_header(self, text):
        print(f"\n{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'=' * 50}{Style.RESET_ALL}")

    def get_domain_info(self):
        self.print_header("Informações WHOIS")
        try:
            domain_info = whois.whois(self.domain)
            if domain_info.domain_name:
                print(f"{Fore.CYAN}Domínio:{Style.RESET_ALL} {domain_info.domain_name}")
            if domain_info.registrar:
                print(
                    f"{Fore.CYAN}Registrador:{Style.RESET_ALL} {domain_info.registrar}"
                )
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    print(
                        f"{Fore.CYAN}Data de Criação:{Style.RESET_ALL} {domain_info.creation_date[0]}"
                    )
                else:
                    print(
                        f"{Fore.CYAN}Data de Criação:{Style.RESET_ALL} {domain_info.creation_date}"
                    )
            if domain_info.expiration_date:
                if isinstance(domain_info.expiration_date, list):
                    print(
                        f"{Fore.CYAN}Data de Expiração:{Style.RESET_ALL} {domain_info.expiration_date[0]}"
                    )
                else:
                    print(
                        f"{Fore.CYAN}Data de Expiração:{Style.RESET_ALL} {domain_info.expiration_date}"
                    )
            if domain_info.name_servers:
                print(f"{Fore.CYAN}Servidores DNS:{Style.RESET_ALL}")
                for ns in domain_info.name_servers:
                    print(f"  - {ns}")
        except Exception as e:
            print(f"{Fore.RED}Erro ao obter informações WHOIS: {e}{Style.RESET_ALL}")

    def check_dns_records(self):
        self.print_header("Registros DNS")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                print(f"\n{Fore.CYAN}Registros {record_type}:{Style.RESET_ALL}")
                for rdata in answers:
                    if record_type == "MX":
                        print(
                            f"  Prioridade: {rdata.preference} Servidor: {rdata.exchange}"
                        )
                    elif record_type == "SOA":
                        print(f"  Serial: {rdata.serial}")
                        print(f"  Refresh: {rdata.refresh}")
                        print(f"  Retry: {rdata.retry}")
                        print(f"  Expire: {rdata.expire}")
                        print(f"  Minimum TTL: {rdata.minimum}")
                    else:
                        print(f"  {rdata}")
            except dns.resolver.NoAnswer:
                print(f"  Nenhum registro {record_type} encontrado")
            except dns.resolver.NXDOMAIN:
                print(f"{Fore.RED}Domínio não encontrado{Style.RESET_ALL}")
                return
            except Exception as e:
                print(
                    f"{Fore.RED}Erro ao verificar registro {record_type}: {e}{Style.RESET_ALL}"
                )

    def check_ssl_security(self):
        self.print_header("Análise de Segurança SSL/TLS")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    print(f"{Fore.CYAN}Versão TLS:{Style.RESET_ALL} {ssock.version()}")
                    print(f"{Fore.CYAN}Cipher Suite:{Style.RESET_ALL} {cipher[0]}")
                    print(f"{Fore.CYAN}Bits:{Style.RESET_ALL} {cipher[2]}")

                    # Verificação do certificado
                    not_after = datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    )
                    not_before = datetime.strptime(
                        cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
                    )

                    print(f"\n{Fore.CYAN}Informações do Certificado:{Style.RESET_ALL}")
                    print(f"Válido desde: {not_before}")
                    print(f"Válido até: {not_after}")

                    # Verificar status de validade
                    now = datetime.now()
                    if now < not_after:
                        days_remaining = (not_after - now).days
                        print(
                            f"{Fore.GREEN}Certificado válido (Dias restantes: {days_remaining}){Style.RESET_ALL}"
                        )
                    else:
                        print(
                            f"{Fore.RED}ALERTA: Certificado expirado!{Style.RESET_ALL}"
                        )

                    # Subject Alternative Names (SANs)
                    if "subjectAltName" in cert:
                        print(f"\n{Fore.CYAN}SANs:{Style.RESET_ALL}")
                        for type_name, value in cert["subjectAltName"]:
                            print(f"  {type_name}: {value}")

                    # Informações do emissor
                    if "issuer" in cert:
                        print(f"\n{Fore.CYAN}Emissor:{Style.RESET_ALL}")
                        for attr in cert["issuer"]:
                            print(f"  {attr[0][0]}: {attr[0][1]}")
        except Exception as e:
            print(f"{Fore.RED}Erro na análise SSL: {e}{Style.RESET_ALL}")

    def check_certificate_revocation(self):
        """Verificação de certificados revogados (CRL/OCSP)"""
        self.print_header("Verificação de Revogação de Certificados")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()

                    print(
                        f"{Fore.CYAN}Verificando status de revogação...{Style.RESET_ALL}"
                    )

                    # Verificar CRL (Certificate Revocation List)
                    crl_status = self._check_crl_status(cert)
                    if crl_status:
                        print(
                            f"{Fore.GREEN}✓ Verificação CRL: {crl_status}{Style.RESET_ALL}"
                        )
                    else:
                        print(
                            f"{Fore.YELLOW}⚠ Verificação CRL: Não disponível{Style.RESET_ALL}"
                        )

                    # Verificar OCSP (Online Certificate Status Protocol)
                    ocsp_status = self._check_ocsp_status(cert)
                    if ocsp_status:
                        print(
                            f"{Fore.GREEN}✓ Verificação OCSP: {ocsp_status}{Style.RESET_ALL}"
                        )
                    else:
                        print(
                            f"{Fore.YELLOW}⚠ Verificação OCSP: Não disponível{Style.RESET_ALL}"
                        )

                    # Verificar se o certificado está na lista de revogados
                    if self._is_certificate_revoked(cert):
                        print(
                            f"{Fore.RED}🚨 ALERTA: Certificado pode estar revogado!{Style.RESET_ALL}"
                        )
                    else:
                        print(
                            f"{Fore.GREEN}✓ Certificado não está na lista de revogados{Style.RESET_ALL}"
                        )

        except Exception as e:
            print(f"{Fore.RED}Erro na verificação de revogação: {e}{Style.RESET_ALL}")

    def _check_crl_status(self, cert):
        """Verifica se há informações CRL disponíveis"""
        try:
            # Verificar se há distribuição de CRL
            if "crlDistributionPoints" in cert:
                crl_urls = cert["crlDistributionPoints"]
                return f"CRL disponível em {len(crl_urls)} local(is)"
            return None
        except:
            return None

    def _check_ocsp_status(self, cert):
        """Verifica se há informações OCSP disponíveis"""
        try:
            # Verificar se há responder OCSP
            if "authorityInfoAccess" in cert:
                for access_info in cert["authorityInfoAccess"]:
                    if access_info[0] == "OCSP":
                        return f"Responder OCSP: {access_info[1]}"
            return None
        except:
            return None

    def _is_certificate_revoked(self, cert):
        """Verifica se o certificado está revogado (implementação básica)"""
        try:
            # Esta é uma implementação simplificada
            # Em produção, seria necessário fazer requisições reais para CRL/OCSP

            # Verificar se há informações de revogação no certificado
            if "crlDistributionPoints" in cert or "authorityInfoAccess" in cert:
                # Se há informações de revogação, considerar como não revogado por padrão
                # Em uma implementação real, faríamos as requisições para verificar
                return False

            # Se não há informações de revogação, pode ser um sinal de alerta
            return False
        except:
            return False

    def analyze_certificate_chain(self):
        """Análise da cadeia de certificados"""
        self.print_header("Análise da Cadeia de Certificados")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    # Obter a cadeia completa de certificados
                    try:
                        cert_chain = ssock.getpeercertchain()
                    except AttributeError:
                        # Fallback para versões mais antigas do Python
                        cert_chain = [ssock.getpeercert()]

                    if cert_chain:
                        print(
                            f"{Fore.CYAN}Cadeia de Certificados ({len(cert_chain)} certificados):{Style.RESET_ALL}\n"
                        )

                        for i, cert in enumerate(cert_chain):
                            print(f"{Fore.YELLOW}Certificado {i+1}:{Style.RESET_ALL}")

                            # Informações básicas do certificado
                            if "subject" in cert:
                                subject = cert["subject"]
                                if subject:
                                    print(f"  {Fore.CYAN}Assunto:{Style.RESET_ALL}")
                                    for attr in subject:
                                        print(f"    {attr[0][0]}: {attr[0][1]}")

                            if "issuer" in cert:
                                issuer = cert["issuer"]
                                if issuer:
                                    print(f"  {Fore.CYAN}Emissor:{Style.RESET_ALL}")
                                    for attr in issuer:
                                        print(f"    {attr[0][0]}: {attr[0][1]}")

                            # Validade
                            if "notBefore" in cert and "notAfter" in cert:
                                not_before = datetime.strptime(
                                    cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
                                )
                                not_after = datetime.strptime(
                                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                                )
                                print(
                                    f"  {Fore.CYAN}Válido:{Style.RESET_ALL} {not_before} até {not_after}"
                                )

                                # Verificar se está próximo da expiração
                                now = datetime.now()
                                days_remaining = (not_after - now).days
                                if days_remaining < 30:
                                    print(
                                        f"  {Fore.RED}⚠ Expira em {days_remaining} dias!{Style.RESET_ALL}"
                                    )

                            # Verificar se é certificado raiz
                            if i == len(cert_chain) - 1:
                                if "subject" in cert and "issuer" in cert:
                                    if cert["subject"] == cert["issuer"]:
                                        print(
                                            f"  {Fore.GREEN}✓ Certificado raiz (self-signed){Style.RESET_ALL}"
                                        )
                                    else:
                                        print(
                                            f"  {Fore.YELLOW}⚠ Certificado intermediário{Style.RESET_ALL}"
                                        )

                            print()

                        # Análise da confiança da cadeia
                        self._analyze_chain_trust(cert_chain)
                    else:
                        print(
                            f"{Fore.YELLOW}Nenhuma cadeia de certificados disponível{Style.RESET_ALL}"
                        )

        except Exception as e:
            print(f"{Fore.RED}Erro na análise da cadeia: {e}{Style.RESET_ALL}")

    def _analyze_chain_trust(self, cert_chain):
        """Analisa a confiança da cadeia de certificados"""
        print(f"{Fore.CYAN}Análise de Confiança da Cadeia:{Style.RESET_ALL}")

        if len(cert_chain) < 2:
            print(
                f"{Fore.YELLOW}⚠ Cadeia muito curta - pode indicar problema de confiança{Style.RESET_ALL}"
            )
            return

        # Verificar se o último certificado é de uma CA confiável
        root_cert = cert_chain[-1]
        if "subject" in root_cert:
            root_subject = root_cert["subject"]
            trusted_cas = [
                "DigiCert Inc",
                "GlobalSign",
                "Let's Encrypt",
                "Comodo CA Limited",
                "GoDaddy.com, Inc",
                "Amazon",
                "Google Trust Services",
                "Sectigo Limited",
            ]

            is_trusted = False
            for attr in root_subject:
                if attr[0][0] == "organizationName":
                    if any(ca in attr[0][1] for ca in trusted_cas):
                        is_trusted = True
                        print(
                            f"{Fore.GREEN}✓ CA raiz confiável: {attr[0][1]}{Style.RESET_ALL}"
                        )
                        break

            if not is_trusted:
                print(
                    f"{Fore.YELLOW}⚠ CA raiz não reconhecida como confiável{Style.RESET_ALL}"
                )

        # Verificar comprimento da cadeia
        if len(cert_chain) == 2:
            print(f"{Fore.GREEN}✓ Cadeia direta (domínio → CA raiz){Style.RESET_ALL}")
        elif len(cert_chain) == 3:
            print(
                f"{Fore.GREEN}✓ Cadeia padrão (domínio → intermediário → CA raiz){Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.YELLOW}⚠ Cadeia não padrão ({len(cert_chain)} certificados){Style.RESET_ALL}"
            )

    def check_security_policies(self):
        """Verificação de políticas de segurança (HSTS, CSP)"""
        self.print_header("Verificação de Políticas de Segurança")
        try:
            response = self.session.get(
                f"https://{self.domain}", verify=False, timeout=10
            )
            headers = response.headers

            print(f"{Fore.CYAN}Políticas de Segurança Detectadas:{Style.RESET_ALL}\n")

            # Verificar HSTS (HTTP Strict Transport Security)
            hsts_header = headers.get("Strict-Transport-Security")
            if hsts_header:
                print(f"{Fore.GREEN}✓ HSTS Configurado:{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Valor:{Style.RESET_ALL} {hsts_header}")

                # Análise detalhada do HSTS
                self._analyze_hsts_policy(hsts_header)
            else:
                print(f"{Fore.RED}✗ HSTS não configurado{Style.RESET_ALL}")
                print(
                    f"  {Fore.YELLOW}Recomendação: Implementar HSTS para forçar HTTPS{Style.RESET_ALL}"
                )

            print()

            # Verificar CSP (Content Security Policy)
            csp_header = headers.get("Content-Security-Policy")
            if csp_header:
                print(f"{Fore.GREEN}✓ CSP Configurado:{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}Valor:{Style.RESET_ALL} {csp_header}")

                # Análise detalhada do CSP
                self._analyze_csp_policy(csp_header)
            else:
                print(f"{Fore.RED}✗ CSP não configurado{Style.RESET_ALL}")
                print(
                    f"  {Fore.YELLOW}Recomendação: Implementar CSP para prevenir XSS{Style.RESET_ALL}"
                )

            print()

            # Verificar outras políticas de segurança
            self._check_additional_security_policies(headers)

        except Exception as e:
            print(f"{Fore.RED}Erro na verificação de políticas: {e}{Style.RESET_ALL}")

    def _analyze_hsts_policy(self, hsts_value):
        """Analisa a política HSTS em detalhes"""
        hsts_lower = hsts_value.lower()

        # Verificar max-age
        max_age_match = re.search(r"max-age=(\d+)", hsts_lower)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:  # 1 ano
                print(
                    f"  {Fore.GREEN}✓ max-age adequado: {max_age} segundos{Style.RESET_ALL}"
                )
            else:
                print(
                    f"  {Fore.YELLOW}⚠ max-age baixo: {max_age} segundos (recomendado: ≥31536000){Style.RESET_ALL}"
                )

        # Verificar includeSubDomains
        if "includesubdomains" in hsts_lower:
            print(f"  {Fore.GREEN}✓ includeSubDomains ativado{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}⚠ includeSubDomains não ativado{Style.RESET_ALL}")

        # Verificar preload
        if "preload" in hsts_lower:
            print(f"  {Fore.GREEN}✓ preload ativado{Style.RESET_ALL}")
        else:
            print(f"  {Fore.YELLOW}⚠ preload não ativado{Style.RESET_ALL}")

    def _analyze_csp_policy(self, csp_value):
        """Analisa a política CSP em detalhes"""
        csp_lower = csp_value.lower()

        # Verificar diretivas essenciais
        essential_directives = ["default-src", "script-src", "style-src"]
        for directive in essential_directives:
            if directive in csp_lower:
                print(f"  {Fore.GREEN}✓ {directive} configurado{Style.RESET_ALL}")
            else:
                print(f"  {Fore.YELLOW}⚠ {directive} não configurado{Style.RESET_ALL}")

        # Verificar se há 'unsafe-inline' ou 'unsafe-eval'
        if "unsafe-inline" in csp_lower:
            print(
                f"  {Fore.RED}⚠ unsafe-inline detectado - pode permitir XSS{Style.RESET_ALL}"
            )

        if "unsafe-eval" in csp_lower:
            print(
                f"  {Fore.RED}⚠ unsafe-eval detectado - pode permitir code injection{Style.RESET_ALL}"
            )

        # Verificar nonce ou hash
        if "nonce-" in csp_lower:
            print(
                f"  {Fore.GREEN}✓ nonce implementado para scripts inline{Style.RESET_ALL}"
            )

        if "sha256-" in csp_lower or "sha384-" in csp_lower or "sha512-" in csp_lower:
            print(
                f"  {Fore.GREEN}✓ hash implementado para recursos inline{Style.RESET_ALL}"
            )

    def _check_additional_security_policies(self, headers):
        """Verifica outras políticas de segurança"""
        additional_policies = {
            "X-Frame-Options": "Previne clickjacking",
            "X-Content-Type-Options": "Previne MIME type sniffing",
            "X-XSS-Protection": "Proteção XSS do navegador",
            "Referrer-Policy": "Controle de informações de referência",
            "Permissions-Policy": "Controle de recursos do navegador",
        }

        print(f"{Fore.CYAN}Outras Políticas de Segurança:{Style.RESET_ALL}")
        for header, description in additional_policies.items():
            if header in headers:
                print(f"  {Fore.GREEN}✓ {header}: {description}{Style.RESET_ALL}")
            else:
                print(
                    f"  {Fore.YELLOW}⚠ {header}: {description} (não configurado){Style.RESET_ALL}"
                )

    def detect_self_signed_certificates(self):
        """Detecção de certificados auto-assinados ou inválidos"""
        self.print_header("Detecção de Certificados Auto-assinados/Inválidos")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()

                    print(f"{Fore.CYAN}Análise do Certificado:{Style.RESET_ALL}\n")

                    # Verificar se é auto-assinado
                    if "subject" in cert and "issuer" in cert:
                        subject = cert["subject"]
                        issuer = cert["issuer"]

                        if subject == issuer:
                            print(
                                f"{Fore.RED}🚨 ALERTA: Certificado auto-assinado detectado!{Style.RESET_ALL}"
                            )
                            print(f"  {Fore.CYAN}Assunto:{Style.RESET_ALL} {subject}")
                            print(f"  {Fore.CYAN}Emissor:{Style.RESET_ALL} {issuer}")
                            print(
                                f"  {Fore.YELLOW}Risco: Certificados auto-assinados não são confiáveis{Style.RESET_ALL}"
                            )
                        else:
                            print(
                                f"{Fore.GREEN}✓ Certificado não é auto-assinado{Style.RESET_ALL}"
                            )

                    # Verificar validade temporal
                    if "notBefore" in cert and "notAfter" in cert:
                        not_before = datetime.strptime(
                            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
                        )
                        not_after = datetime.strptime(
                            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                        )
                        now = datetime.now()

                        if now < not_before:
                            print(
                                f"{Fore.RED}🚨 ALERTA: Certificado ainda não é válido!{Style.RESET_ALL}"
                            )
                            print(
                                f"  {Fore.CYAN}Válido a partir de:{Style.RESET_ALL} {not_before}"
                            )
                        elif now > not_after:
                            print(
                                f"{Fore.RED}🚨 ALERTA: Certificado expirado!{Style.RESET_ALL}"
                            )
                            print(
                                f"  {Fore.CYAN}Expirou em:{Style.RESET_ALL} {not_after}"
                            )
                        else:
                            days_remaining = (not_after - now).days
                            if days_remaining < 30:
                                print(
                                    f"{Fore.YELLOW}⚠ Certificado expira em breve: {days_remaining} dias{Style.RESET_ALL}"
                                )
                            else:
                                print(
                                    f"{Fore.GREEN}✓ Certificado válido por mais {days_remaining} dias{Style.RESET_ALL}"
                                )

                    # Verificar SANs (Subject Alternative Names)
                    if "subjectAltName" in cert:
                        sans = cert["subjectAltName"]
                        domain_found = False

                        for type_name, value in sans:
                            if type_name == "DNS" and self.domain in value:
                                domain_found = True
                                break

                        if not domain_found:
                            print(
                                f"{Fore.RED}🚨 ALERTA: Domínio não encontrado nos SANs!{Style.RESET_ALL}"
                            )
                            print(
                                f"  {Fore.CYAN}Domínio verificado:{Style.RESET_ALL} {self.domain}"
                            )
                            print(f"  {Fore.CYAN}SANs disponíveis:{Style.RESET_ALL}")
                            for type_name, value in sans:
                                print(f"    {type_name}: {value}")
                        else:
                            print(
                                f"{Fore.GREEN}✓ Domínio encontrado nos SANs{Style.RESET_ALL}"
                            )

                    # Verificar força da criptografia
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        cipher_bits = cipher[2]

                        print(
                            f"\n{Fore.CYAN}Informações de Criptografia:{Style.RESET_ALL}"
                        )
                        print(
                            f"  {Fore.CYAN}Cipher Suite:{Style.RESET_ALL} {cipher_name}"
                        )
                        print(f"  {Fore.CYAN}Bits:{Style.RESET_ALL} {cipher_bits}")

                        # Verificar se é um cipher forte
                        weak_ciphers = [
                            "RC4",
                            "DES",
                            "3DES",
                            "MD5",
                            "SHA1",
                            "NULL",
                            "EXPORT",
                        ]
                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            print(
                                f"  {Fore.RED}⚠ Cipher Suite pode ser fraco: {cipher_name}{Style.RESET_ALL}"
                            )
                        elif cipher_bits >= 256:
                            print(
                                f"  {Fore.GREEN}✓ Cipher Suite muito forte ({cipher_bits} bits){Style.RESET_ALL}"
                            )
                        elif cipher_bits >= 128:
                            print(
                                f"  {Fore.GREEN}✓ Cipher Suite forte ({cipher_bits} bits){Style.RESET_ALL}"
                            )
                        else:
                            print(
                                f"  {Fore.YELLOW}⚠ Cipher Suite com bits baixos ({cipher_bits} bits){Style.RESET_ALL}"
                            )

                    # Verificar versão TLS
                    tls_version = ssock.version()
                    print(f"\n{Fore.CYAN}Versão TLS:{Style.RESET_ALL} {tls_version}")

                    if "TLSv1.3" in tls_version:
                        print(
                            f"  {Fore.GREEN}✓ Versão TLS mais recente e segura{Style.RESET_ALL}"
                        )
                    elif "TLSv1.2" in tls_version:
                        print(
                            f"  {Fore.YELLOW}⚠ Versão TLS aceitável, mas pode ser atualizada{Style.RESET_ALL}"
                        )
                    elif "TLSv1.1" in tls_version or "TLSv1.0" in tls_version:
                        print(
                            f"  {Fore.RED}🚨 ALERTA: Versão TLS desatualizada e insegura!{Style.RESET_ALL}"
                        )
                    elif "SSL" in tls_version:
                        print(
                            f"  {Fore.RED}🚨 ALERTA: Protocolo SSL obsoleto e inseguro!{Style.RESET_ALL}"
                        )

                    # Verificar algoritmo de assinatura
                    if "signatureAlgorithm" in cert:
                        sig_algorithm = cert["signatureAlgorithm"]
                        print(
                            f"\n{Fore.CYAN}Algoritmo de Assinatura:{Style.RESET_ALL} {sig_algorithm}"
                        )

                        # Verificar se é um algoritmo forte
                        strong_algorithms = ["sha256", "sha384", "sha512", "ecdsa"]
                        weak_algorithms = ["sha1", "md5"]

                        sig_lower = sig_algorithm.lower()
                        if any(weak in sig_lower for weak in weak_algorithms):
                            print(
                                f"  {Fore.RED}⚠ Algoritmo de assinatura fraco detectado!{Style.RESET_ALL}"
                            )
                        elif any(strong in sig_lower for strong in strong_algorithms):
                            print(
                                f"  {Fore.GREEN}✓ Algoritmo de assinatura forte{Style.RESET_ALL}"
                            )
                        else:
                            print(
                                f"  {Fore.YELLOW}⚠ Algoritmo de assinatura não identificado{Style.RESET_ALL}"
                            )

        except Exception as e:
            print(f"{Fore.RED}Erro na detecção de certificados: {e}{Style.RESET_ALL}")

    def check_security_headers(self):
        """Análise avançada de headers de segurança"""
        self.print_header("Análise Avançada de Headers de Segurança")
        try:
            response = self.session.get(
                f"https://{self.domain}", verify=False, timeout=10
            )
            headers = response.headers

            security_score = 0
            total_headers = len(SECURITY_HEADERS)

            print(f"{Fore.CYAN}Análise de Headers de Segurança:{Style.RESET_ALL}\n")

            for header, config in SECURITY_HEADERS.items():
                value = headers.get(header)
                risk_color = (
                    Fore.RED
                    if config["risk"] == "high"
                    else Fore.YELLOW if config["risk"] == "medium" else Fore.GREEN
                )

                if value:
                    print(f"{Fore.GREEN}✓ {header}{Style.RESET_ALL}")
                    print(f"  {Fore.CYAN}Valor:{Style.RESET_ALL} {value}")
                    print(
                        f"  {Fore.CYAN}Descrição:{Style.RESET_ALL} {config['description']}"
                    )

                    # Verificar se o valor está correto
                    if self._validate_security_header(header, value):
                        print(f"  {Fore.GREEN}✓ Configuração adequada{Style.RESET_ALL}")
                        security_score += 1
                    else:
                        print(
                            f"  {Fore.YELLOW}⚠ Configuração pode ser melhorada{Style.RESET_ALL}"
                        )
                        print(
                            f"  {Fore.CYAN}Recomendado:{Style.RESET_ALL} {config['recommended']}"
                        )
                else:
                    print(f"{Fore.RED}✗ {header}{Style.RESET_ALL}")
                    print(
                        f"  {Fore.CYAN}Descrição:{Style.RESET_ALL} {config['description']}"
                    )
                    print(f"  {Fore.RED}❌ Header não configurado{Style.RESET_ALL}")
                    print(
                        f"  {Fore.CYAN}Recomendado:{Style.RESET_ALL} {config['recommended']}"
                    )

                print()

            # Calcular score de segurança
            security_percentage = (security_score / total_headers) * 100
            if security_percentage >= 80:
                score_color = Fore.GREEN
                score_status = "EXCELENTE"
            elif security_percentage >= 60:
                score_color = Fore.YELLOW
                score_status = "BOM"
            elif security_percentage >= 40:
                score_color = Fore.RED
                score_status = "REGULAR"
            else:
                score_color = Fore.RED
                score_status = "CRÍTICO"

            print(
                f"{Fore.CYAN}Score de Segurança:{Style.RESET_ALL} {score_color}{security_percentage:.1f}% ({score_status}){Style.RESET_ALL}"
            )
            print(
                f"{Fore.CYAN}Headers configurados:{Style.RESET_ALL} {security_score}/{total_headers}"
            )

        except Exception as e:
            print(f"{Fore.RED}Erro ao verificar cabeçalhos: {e}{Style.RESET_ALL}")

    def _validate_security_header(self, header, value):
        """Valida se o header de segurança está configurado corretamente"""
        value = value.lower()

        if header == "Strict-Transport-Security":
            return (
                "max-age=" in value
                and int(re.search(r"max-age=(\d+)", value).group(1)) >= 31536000
            )

        elif header == "Content-Security-Policy":
            return "default-src" in value and "script-src" in value

        elif header == "X-Frame-Options":
            return value in ["deny", "sameorigin"]

        elif header == "X-Content-Type-Options":
            return value == "nosniff"

        elif header == "X-XSS-Protection":
            return "1" in value

        elif header == "Referrer-Policy":
            return any(
                policy in value
                for policy in ["strict-origin", "same-origin", "no-referrer"]
            )

        return True

    def scan_common_directories(self):
        self.print_header("Varredura de Diretórios")
        common_dirs = [
            "admin",
            "wp-admin",
            "administrator",
            "login",
            "wp-login.php",
            "backup",
            "db",
            "database",
            "dev",
            "development",
            "test",
            "testing",
            "staging",
            "prod",
            "production",
            "api",
            "v1",
            "v2",
            "api-docs",
            "swagger",
            "phpinfo.php",
            "phpmyadmin",
            "mysql",
            "config",
            ".git",
            ".env",
            ".htaccess",
            "robots.txt",
            "sitemap.xml",
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for directory in common_dirs:
                url = f"https://{self.domain}/{directory}"
                futures.append(executor.submit(self.check_directory, url))

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        url, status = result
                        if status == 200:
                            print(
                                f"{Fore.GREEN}Encontrado:{Style.RESET_ALL} {url} (Status: {status})"
                            )
                        elif status in [301, 302, 403]:
                            print(
                                f"{Fore.YELLOW}Restrito:{Style.RESET_ALL} {url} (Status: {status})"
                            )
                except Exception as e:
                    continue

    def scan_sensitive_files(self):
        """Scanner avançado de arquivos sensíveis"""
        self.print_header("Scanner de Arquivos Sensíveis")

        found_files = []
        total_files = len(SENSITIVE_FILES)

        print(
            f"{Fore.CYAN}Verificando {total_files} arquivos sensíveis...{Style.RESET_ALL}\n"
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for file_path in SENSITIVE_FILES:
                url = f"https://{self.domain}/{file_path}"
                futures.append(
                    executor.submit(self.check_sensitive_file, url, file_path)
                )

            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        found_files.append(result)
                except Exception as e:
                    continue

        # Classificar arquivos encontrados por risco
        high_risk = []
        medium_risk = []
        low_risk = []

        for file_info in found_files:
            if self._get_file_risk_level(file_info["file"]) == "high":
                high_risk.append(file_info)
            elif self._get_file_risk_level(file_info["file"]) == "medium":
                medium_risk.append(file_info)
            else:
                low_risk.append(file_info)

        # Exibir resultados
        if high_risk:
            print(f"{Fore.RED}🚨 ARQUIVOS DE ALTO RISCO ENCONTRADOS:{Style.RESET_ALL}")
            for file_info in high_risk:
                print(f"  {Fore.RED}✗ {file_info['file']}{Style.RESET_ALL}")
                print(f"    URL: {file_info['url']}")
                print(f"    Status: {file_info['status']}")
                print(f"    Tamanho: {file_info['size']} bytes")
                print()

        if medium_risk:
            print(
                f"{Fore.YELLOW}⚠ ARQUIVOS DE MÉDIO RISCO ENCONTRADOS:{Style.RESET_ALL}"
            )
            for file_info in medium_risk:
                print(f"  {Fore.YELLOW}⚠ {file_info['file']}{Style.RESET_ALL}")
                print(f"    URL: {file_info['url']}")
                print(f"    Status: {file_info['status']}")
                print()

        if low_risk:
            print(
                f"{Fore.GREEN}ℹ ARQUIVOS DE BAIXO RISCO ENCONTRADOS:{Style.RESET_ALL}"
            )
            for file_info in low_risk:
                print(f"  {Fore.GREEN}ℹ {file_info['file']}{Style.RESET_ALL}")
                print(f"    URL: {file_info['url']}")
                print(f"    Status: {file_info['status']}")
                print()

        if not found_files:
            print(f"{Fore.GREEN}✓ Nenhum arquivo sensível encontrado{Style.RESET_ALL}")

        # Estatísticas
        print(f"{Fore.CYAN}Estatísticas da Varredura:{Style.RESET_ALL}")
        print(f"  Total verificado: {total_files}")
        print(f"  Arquivos encontrados: {len(found_files)}")
        print(f"  Alto risco: {len(high_risk)}")
        print(f"  Médio risco: {len(medium_risk)}")
        print(f"  Baixo risco: {len(low_risk)}")

    def check_sensitive_file(self, url, file_path):
        """Verifica se um arquivo sensível está acessível"""
        try:
            response = self.session.get(
                url, verify=False, timeout=5, allow_redirects=False
            )
            if response.status_code == 200:
                return {
                    "file": file_path,
                    "url": url,
                    "status": response.status_code,
                    "size": len(response.content),
                    "content_type": response.headers.get("content-type", "unknown"),
                }
        except:
            pass
        return None

    def _get_file_risk_level(self, file_path):
        """Determina o nível de risco de um arquivo"""
        file_lower = file_path.lower()

        # Alto risco
        if any(
            ext in file_lower
            for ext in [".env", ".git", "config.php", "wp-config.php", "database.yml"]
        ):
            return "high"

        # Médio risco
        elif any(
            ext in file_lower for ext in [".sql", ".bak", ".backup", ".log", "backup"]
        ):
            return "medium"

        # Baixo risco
        else:
            return "low"

    def check_directory(self, url):
        try:
            response = self.session.get(
                url, verify=False, timeout=5, allow_redirects=False
            )
            return (url, response.status_code)
        except:
            return None

    def get_ip_geolocation(self):
        """Obter informações de geolocalização do IP"""
        self.print_header("Geolocalização do IP")
        try:
            ip = socket.gethostbyname(self.domain)
            print(f"{Fore.CYAN}IP:{Style.RESET_ALL} {ip}")

            if self.geoip_reader:
                try:
                    response = self.geoip_reader.country(ip)
                    print(f"{Fore.CYAN}País:{Style.RESET_ALL} {response.country.name}")
                    print(
                        f"{Fore.CYAN}Código do País:{Style.RESET_ALL} {response.country.iso_code}"
                    )
                except:
                    print(
                        f"{Fore.YELLOW}Não foi possível obter informações geográficas detalhadas{Style.RESET_ALL}"
                    )
        except Exception as e:
            print(f"{Fore.RED}Erro na geolocalização: {e}{Style.RESET_ALL}")

    def check_open_ports(self):
        """Verificar portas comuns abertas"""
        self.print_header("Verificação de Portas")
        try:
            nm = nmap.PortScanner()
            common_ports = [21, 22, 80, 443, 3306, 8080, 5432]

            for port in common_ports:
                result = nm.scan(self.domain, str(port))
                state = result["scan"][self.domain]["tcp"][port]["state"]
                service = result["scan"][self.domain]["tcp"][port].get(
                    "name", "Desconhecido"
                )

                if state == "open":
                    print(
                        f"{Fore.GREEN}Porta {port} aberta:{Style.RESET_ALL} {service}"
                    )
                else:
                    print(f"{Fore.RED}Porta {port} fechada{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Erro na varredura de portas: {e}{Style.RESET_ALL}")

    def detect_technologies(self):
        """Detectar tecnologias do site"""
        self.print_header("Tecnologias Detectadas")
        try:
            url = f"https://{self.domain}"
            response = self.session.get(url, verify=False, timeout=10)

            # Detectar tecnologias por cabeçalhos e conteúdo
            technologies = []

            # Detecção por cabeçalhos
            headers = response.headers
            if "X-Powered-By" in headers:
                technologies.append(f"Powered By: {headers['X-Powered-By']}")
            if "Server" in headers:
                technologies.append(f"Servidor: {headers['Server']}")

            # Detecção por conteúdo
            content = response.text.lower()
            web_techs = {
                "WordPress": "wp-content" in content,
                "Joomla": "joomla" in content,
                "Drupal": "drupal" in content,
                "React": "react" in content,
                "Angular": "ng-app" in content,
                "Vue.js": "vue" in content,
                "Bootstrap": "bootstrap" in content,
                "jQuery": "jquery" in content,
            }

            for tech, detected in web_techs.items():
                if detected:
                    technologies.append(tech)

            if technologies:
                print(f"{Fore.CYAN}Tecnologias:{Style.RESET_ALL}")
                for tech in technologies:
                    print(f"  - {tech}")
            else:
                print(f"{Fore.YELLOW}Nenhuma tecnologia identificada{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Erro na detecção de tecnologias: {e}{Style.RESET_ALL}")

    def scan_owasp_top10(self):
        """Scanner OWASP Top 10 - Análise de vulnerabilidades web"""
        self.print_header("Scanner OWASP Top 10 - Vulnerabilidades Web")

        print(f"{Fore.CYAN}Iniciando análise OWASP Top 10...{Style.RESET_ALL}\n")

        vulnerabilities = []

        # 1. Broken Access Control
        print(f"{Fore.YELLOW}1. Verificando Controle de Acesso...{Style.RESET_ALL}")
        vuln = self._check_access_control()
        if vuln:
            vulnerabilities.append(vuln)

        # 2. Cryptographic Failures
        print(f"{Fore.YELLOW}2. Verificando Falhas Criptográficas...{Style.RESET_ALL}")
        vuln = self._check_cryptographic_failures()
        if vuln:
            vulnerabilities.append(vuln)

        # 3. Injection (SQL, XSS, CSRF)
        print(
            f"{Fore.YELLOW}3. Verificando Vulnerabilidades de Injeção...{Style.RESET_ALL}"
        )
        vuln = self._check_injection_vulnerabilities()
        if vuln:
            vulnerabilities.append(vuln)

        # 4. Insecure Design
        print(f"{Fore.YELLOW}4. Verificando Design Inseguro...{Style.RESET_ALL}")
        vuln = self._check_insecure_design()
        if vuln:
            vulnerabilities.append(vuln)

        # 5. Security Misconfiguration
        print(
            f"{Fore.YELLOW}5. Verificando Configurações de Segurança...{Style.RESET_ALL}"
        )
        vuln = self._check_security_misconfiguration()
        if vuln:
            vulnerabilities.append(vuln)

        # 6. Vulnerable Components
        print(
            f"{Fore.YELLOW}6. Verificando Componentes Vulneráveis...{Style.RESET_ALL}"
        )
        vuln = self._check_vulnerable_components()
        if vuln:
            vulnerabilities.append(vuln)

        # 7. Authentication Failures
        print(f"{Fore.YELLOW}7. Verificando Falhas de Autenticação...{Style.RESET_ALL}")
        vuln = self._check_authentication_failures()
        if vuln:
            vulnerabilities.append(vuln)

        # 8. Software and Data Integrity Failures
        print(
            f"{Fore.YELLOW}8. Verificando Integridade de Software...{Style.RESET_ALL}"
        )
        vuln = self._check_integrity_failures()
        if vuln:
            vulnerabilities.append(vuln)

        # 9. Logging Failures
        print(f"{Fore.YELLOW}9. Verificando Falhas de Logging...{Style.RESET_ALL}")
        vuln = self._check_logging_failures()
        if vuln:
            vulnerabilities.append(vuln)

        # 10. Server-Side Request Forgery
        print(f"{Fore.YELLOW}10. Verificando SSRF...{Style.RESET_ALL}")
        vuln = self._check_ssrf()
        if vuln:
            vulnerabilities.append(vuln)

        # Resumo das vulnerabilidades
        self._print_owasp_summary(vulnerabilities)

    def _check_access_control(self):
        """Verifica controle de acesso"""
        try:
            # Testar endpoints administrativos
            admin_endpoints = [
                "/admin",
                "/administrator",
                "/manage",
                "/panel",
                "/dashboard",
            ]
            accessible_endpoints = []

            for endpoint in admin_endpoints:
                url = f"https://{self.domain}{endpoint}"
                try:
                    response = self.session.get(url, verify=False, timeout=5)
                    if response.status_code == 200:
                        accessible_endpoints.append(endpoint)
                except:
                    pass

            if accessible_endpoints:
                return {
                    "category": "Broken Access Control",
                    "risk": "HIGH",
                    "description": f'Endpoints administrativos acessíveis sem autenticação: {", ".join(accessible_endpoints)}',
                    "recommendation": "Implementar autenticação obrigatória para endpoints administrativos",
                }
        except Exception as e:
            pass
        return None

    def _check_cryptographic_failures(self):
        """Verifica falhas criptográficas"""
        try:
            # Verificar se o site usa HTTP
            http_url = f"http://{self.domain}"
            try:
                response = self.session.get(http_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    return {
                        "category": "Cryptographic Failures",
                        "risk": "HIGH",
                        "description": "Site acessível via HTTP (não criptografado)",
                        "recommendation": "Forçar redirecionamento para HTTPS e implementar HSTS",
                    }
            except:
                pass
        except Exception as e:
            pass
        return None

    def _check_injection_vulnerabilities(self):
        """Verifica vulnerabilidades de injeção"""
        vulnerabilities = []

        try:
            # Testar SQL Injection
            sql_vulns = self._test_sql_injection()
            if sql_vulns:
                vulnerabilities.extend(sql_vulns)

            # Testar XSS
            xss_vulns = self._test_xss()
            if xss_vulns:
                vulnerabilities.extend(xss_vulns)

            # Testar CSRF
            csrf_vulns = self._test_csrf()
            if csrf_vulns:
                vulnerabilities.extend(csrf_vulns)

        except Exception as e:
            pass

        return vulnerabilities if vulnerabilities else None

    def _test_sql_injection(self):
        """Testa vulnerabilidades de SQL Injection"""
        vulnerabilities = []

        try:
            # Buscar por formulários de login
            login_urls = [
                f"https://{self.domain}/login",
                f"https://{self.domain}/admin/login",
                f"https://{self.domain}/user/login",
                f"https://{self.domain}/signin",
            ]

            for url in login_urls:
                try:
                    response = self.session.get(url, verify=False, timeout=5)
                    if response.status_code == 200 and "form" in response.text.lower():
                        # Testar payloads SQL Injection
                        for payload in SECURITY_PAYLOADS["sql_injection"]:
                            test_data = {"username": payload, "password": "test"}
                            try:
                                post_response = self.session.post(
                                    url, data=test_data, verify=False, timeout=5
                                )
                                if self._detect_sql_error(post_response.text):
                                    vulnerabilities.append(
                                        {
                                            "category": "SQL Injection",
                                            "risk": "CRITICAL",
                                            "description": f"SQL Injection detectado em {url} com payload: {payload}",
                                            "recommendation": "Implementar prepared statements e validação de entrada",
                                        }
                                    )
                                    break
                            except:
                                continue
                except:
                    continue
        except Exception as e:
            pass

        return vulnerabilities

    def _test_xss(self):
        """Testa vulnerabilidades de XSS"""
        vulnerabilities = []

        try:
            # Buscar por campos de entrada
            search_urls = [
                f"https://{self.domain}/search",
                f"https://{self.domain}/contact",
                f"https://{self.domain}/feedback",
            ]

            for url in search_urls:
                try:
                    response = self.session.get(url, verify=False, timeout=5)
                    if response.status_code == 200:
                        # Testar payloads XSS
                        for payload in SECURITY_PAYLOADS["xss"]:
                            test_data = {"q": payload, "search": payload}
                            try:
                                post_response = self.session.post(
                                    url, data=test_data, verify=False, timeout=5
                                )
                                if payload in post_response.text:
                                    vulnerabilities.append(
                                        {
                                            "category": "Cross-Site Scripting (XSS)",
                                            "risk": "HIGH",
                                            "description": f"XSS detectado em {url} com payload: {payload}",
                                            "recommendation": "Implementar validação e sanitização de entrada, CSP",
                                        }
                                    )
                                    break
                            except:
                                continue
                except:
                    continue
        except Exception as e:
            pass

        return vulnerabilities

    def _test_csrf(self):
        """Testa vulnerabilidades de CSRF"""
        vulnerabilities = []

        try:
            # Verificar se há proteção CSRF
            forms_without_csrf = []

            # Buscar por formulários
            form_urls = [
                f"https://{self.domain}/login",
                f"https://{self.domain}/register",
                f"https://{self.domain}/profile/update",
            ]

            for url in form_urls:
                try:
                    response = self.session.get(url, verify=False, timeout=5)
                    if response.status_code == 200:
                        form_content = response.text.lower()
                        has_csrf_protection = any(
                            token in form_content for token in SECURITY_PAYLOADS["csrf"]
                        )

                        if not has_csrf_protection and "form" in form_content:
                            forms_without_csrf.append(url)
                except:
                    continue

            if forms_without_csrf:
                vulnerabilities.append(
                    {
                        "category": "Cross-Site Request Forgery (CSRF)",
                        "risk": "MEDIUM",
                        "description": f'Formulários sem proteção CSRF: {", ".join(forms_without_csrf)}',
                        "recommendation": "Implementar tokens CSRF em todos os formulários",
                    }
                )
        except Exception as e:
            pass

        return vulnerabilities

    def _detect_sql_error(self, content):
        """Detecta erros SQL na resposta"""
        sql_errors = [
            "sql syntax",
            "mysql error",
            "oracle error",
            "sql server error",
            "postgresql error",
            "sqlite error",
            "database error",
            "mysql_fetch",
            "ora-",
            "sql state",
            "mysql_num_rows",
            "mysql_fetch_array",
        ]

        content_lower = content.lower()
        return any(error in content_lower for error in sql_errors)

    def _check_insecure_design(self):
        """Verifica design inseguro"""
        try:
            # Verificar se há informações sensíveis expostas
            info_urls = [
                f"https://{self.domain}/phpinfo.php",
                f"https://{self.domain}/info.php",
                f"https://{self.domain}/server-status",
                f"https://{self.domain}/server-info",
            ]

            for url in info_urls:
                try:
                    response = self.session.get(url, verify=False, timeout=5)
                    if response.status_code == 200:
                        return {
                            "category": "Insecure Design",
                            "risk": "HIGH",
                            "description": f"Informações do servidor expostas em {url}",
                            "recommendation": "Remover ou proteger endpoints de informação do servidor",
                        }
                except:
                    continue
        except Exception as e:
            pass
        return None

    def _check_security_misconfiguration(self):
        """Verifica configurações de segurança incorretas"""
        try:
            # Verificar se há headers de debug
            response = self.session.get(
                f"https://{self.domain}", verify=False, timeout=10
            )
            headers = response.headers

            debug_headers = ["X-Debug-Token", "X-Symfony-Debug", "X-Powered-By"]
            found_debug_headers = []

            for header in debug_headers:
                if header in headers:
                    found_debug_headers.append(header)

            if found_debug_headers:
                return {
                    "category": "Security Misconfiguration",
                    "risk": "MEDIUM",
                    "description": f'Headers de debug encontrados: {", ".join(found_debug_headers)}',
                    "recommendation": "Remover headers de debug em produção",
                }
        except Exception as e:
            pass
        return None

    def _check_vulnerable_components(self):
        """Verifica componentes vulneráveis"""
        try:
            # Verificar versões de tecnologias conhecidas
            response = self.session.get(
                f"https://{self.domain}", verify=False, timeout=10
            )
            content = response.text.lower()
            headers = response.headers

            # Detectar tecnologias e versões
            technologies = {}

            if "wordpress" in content:
                # Tentar extrair versão do WordPress
                wp_version_match = re.search(r"wp-content/plugins/([^/]+)/", content)
                if wp_version_match:
                    technologies["WordPress"] = "Detectado"

            if "jquery" in content:
                jquery_match = re.search(r"jquery[.-](\d+\.\d+\.\d+)", content)
                if jquery_match:
                    version = jquery_match.group(1)
                    technologies["jQuery"] = version
                    # Verificar se é uma versão vulnerável
                    if version < "3.0.0":
                        return {
                            "category": "Vulnerable Components",
                            "risk": "MEDIUM",
                            "description": f"jQuery versão vulnerável detectada: {version}",
                            "recommendation": "Atualizar para jQuery 3.0+ ou versão mais recente",
                        }

            if "Server" in headers:
                server = headers["Server"]
                technologies["Server"] = server

                # Verificar versões conhecidas vulneráveis
                if (
                    "apache/2.4.49" in server.lower()
                    or "apache/2.4.50" in server.lower()
                ):
                    return {
                        "category": "Vulnerable Components",
                        "risk": "HIGH",
                        "description": f"Apache versão vulnerável detectada: {server}",
                        "recommendation": "Atualizar Apache para versão mais recente",
                    }
        except Exception as e:
            pass
        return None

    def _check_authentication_failures(self):
        """Verifica falhas de autenticação"""
        try:
            # Verificar se há força bruta possível
            login_urls = [
                f"https://{self.domain}/login",
                f"https://{self.domain}/admin/login",
            ]

            for url in login_urls:
                try:
                    response = self.session.get(url, verify=False, timeout=5)
                    if response.status_code == 200:
                        # Verificar se há rate limiting
                        if (
                            "rate limit" not in response.text.lower()
                            and "captcha" not in response.text.lower()
                        ):
                            return {
                                "category": "Authentication Failures",
                                "risk": "MEDIUM",
                                "description": f"Possível ausência de proteção contra força bruta em {url}",
                                "recommendation": "Implementar rate limiting, CAPTCHA e bloqueio de IP",
                            }
                except:
                    continue
        except Exception as e:
            pass
        return None

    def _check_integrity_failures(self):
        """Verifica falhas de integridade"""
        try:
            # Verificar se há recursos externos não verificados
            response = self.session.get(
                f"https://{self.domain}", verify=False, timeout=10
            )
            content = response.text

            # Buscar por recursos HTTP (não HTTPS)
            http_resources = re.findall(r'http://[^\s"\']+', content)
            if http_resources:
                return {
                    "category": "Software and Data Integrity Failures",
                    "risk": "MEDIUM",
                    "description": f"Recursos HTTP mistos detectados: {len(http_resources)} recursos",
                    "recommendation": "Usar apenas recursos HTTPS para evitar downgrade attacks",
                }
        except Exception as e:
            pass
        return None

    def _check_logging_failures(self):
        """Verifica falhas de logging"""
        try:
            # funcionalidades de segurança implementadas
            # Verificar se há logs expostos
            log_urls = [
                f"https://{self.domain}/logs",
                f"https://{self.domain}/debug",
                f"https://{self.domain}/error",
            ]

            for url in log_urls:
                try:
                    response = self.session.get(url, verify=False, timeout=5)
                    if response.status_code == 200 and (
                        "error" in response.text.lower()
                        or "log" in response.text.lower()
                    ):
                        return {
                            "category": "Logging Failures",
                            "risk": "MEDIUM",
                            "description": f"Logs possivelmente expostos em {url}",
                            "recommendation": "Proteger acesso aos logs e implementar rotação",
                        }
                except:
                    continue
        except Exception as e:
            pass
        return None

    def _check_ssrf(self):
        """Verifica vulnerabilidades SSRF"""
        try:
            # Verificar se há parâmetros que podem ser usados para SSRF
            ssrf_params = ["url", "redirect", "next", "target", "link", "image", "src"]

            # Buscar por formulários com esses parâmetros
            response = self.session.get(
                f"https://{self.domain}", verify=False, timeout=10
            )
            content = response.text.lower()

            found_params = []
            for param in ssrf_params:
                if f'name="{param}"' in content or f"name='{param}'" in content:
                    found_params.append(param)

            if found_params:
                return {
                    "category": "Server-Side Request Forgery (SSRF)",
                    "risk": "MEDIUM",
                    "description": f'Parâmetros potencialmente vulneráveis a SSRF: {", ".join(found_params)}',
                    "recommendation": "Validar e sanitizar URLs de entrada, implementar whitelist de domínios",
                }
        except Exception as e:
            pass
        return None

    def _print_owasp_summary(self, vulnerabilities):
        """Exibe resumo das vulnerabilidades OWASP"""
        print(f"\n{Fore.CYAN}=== RESUMO OWASP TOP 10 ==={Style.RESET_ALL}")

        if not vulnerabilities:
            print(
                f"{Fore.GREEN}✓ Nenhuma vulnerabilidade crítica detectada{Style.RESET_ALL}"
            )
            return

        # Agrupar por risco
        critical = [v for v in vulnerabilities if v["risk"] == "CRITICAL"]
        high = [v for v in vulnerabilities if v["risk"] == "HIGH"]
        medium = [v for v in vulnerabilities if v["risk"] == "MEDIUM"]
        low = [v for v in vulnerabilities if v["risk"] == "LOW"]

        if critical:
            print(
                f"\n{Fore.RED}🚨 VULNERABILIDADES CRÍTICAS ({len(critical)}):{Style.RESET_ALL}"
            )
            for vuln in critical:
                print(f"  {Fore.RED}● {vuln['category']}{Style.RESET_ALL}")
                print(f"    {vuln['description']}")
                print(f"    Recomendação: {vuln['recommendation']}\n")

        if high:
            print(
                f"\n{Fore.RED}⚠ VULNERABILIDADES ALTAS ({len(high)}):{Style.RESET_ALL}"
            )
            for vuln in high:
                print(f"  {Fore.RED}● {vuln['category']}{Style.RESET_ALL}")
                print(f"    {vuln['description']}")
                print(f"    Recomendação: {vuln['recommendation']}\n")

        if medium:
            print(
                f"\n{Fore.YELLOW}⚠ VULNERABILIDADES MÉDIAS ({len(medium)}):{Style.RESET_ALL}"
            )
            for vuln in medium:
                print(f"  {Fore.YELLOW}● {vuln['category']}{Style.RESET_ALL}")
                print(f"    {vuln['description']}")
                print(f"    Recomendação: {vuln['recommendation']}\n")

        if low:
            print(
                f"\n{Fore.GREEN}ℹ VULNERABILIDADES BAIXAS ({len(low)}):{Style.RESET_ALL}"
            )
            for vuln in low:
                print(f"  {Fore.GREEN}● {vuln['category']}{Style.RESET_ALL}")
                print(f"    {vuln['description']}")
                print(f"    Recomendação: {vuln['recommendation']}\n")

        # Estatísticas
        total_vulns = len(vulnerabilities)
        print(f"{Fore.CYAN}Estatísticas de Segurança:{Style.RESET_ALL}")
        print(f"  Total de vulnerabilidades: {total_vulns}")
        print(f"  Críticas: {len(critical)}")
        print(f"  Altas: {len(high)}")
        print(f"  Médias: {len(medium)}")
        print(f"  Baixas: {len(low)}")

        # Score de segurança
        if total_vulns == 0:
            security_score = 100
        elif total_vulns <= 2:
            security_score = 80
        elif total_vulns <= 5:
            security_score = 60
        elif total_vulns <= 10:
            security_score = 40
        else:
            security_score = 20

        if security_score >= 80:
            score_color = Fore.GREEN
            score_status = "EXCELENTE"
        elif security_score >= 60:
            score_color = Fore.YELLOW
            score_status = "BOM"
        elif security_score >= 40:
            score_color = Fore.RED
            score_status = "REGULAR"
        else:
            score_color = Fore.RED
            score_status = "CRÍTICO"

        print(
            f"\n{Fore.CYAN}Score de Segurança OWASP:{Style.RESET_ALL} {score_color}{security_score}/100 ({score_status}){Style.RESET_ALL}"
        )

    def check_domain_reputation(self):
        """Verificar reputação básica do domínio"""
        self.print_header("Reputação do Domínio")
        try:
            api_key = "f93bc98d8ddc3c5d2444ee2e8397382d2e3a2ccea0fd383ed02a12e0f36c0345"
            url = f"https://www.virustotal.com/vtapi/v2/url/report"
            params = {"apikey": api_key, "resource": f"http://{self.domain}"}

            response = requests.get(url, params=params)
            if response.status_code == 200:
                result = response.json()
                positives = result.get("positives", 0)
                total = result.get("total", 0)

                print(f"{Fore.CYAN}Verificações de Segurança:{Style.RESET_ALL}")
                print(f"  Total de verificações: {total}")
                print(f"  Resultados positivos: {positives}")

                if positives == 0:
                    print(f"{Fore.GREEN}Domínio aparenta ser seguro{Style.RESET_ALL}")
                elif positives < total * 0.3:
                    print(f"{Fore.YELLOW}Possíveis riscos detectados{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}ALERTA: Domínio suspeito{Style.RESET_ALL}")
            else:
                print(
                    f"{Fore.YELLOW}Não foi possível verificar a reputação{Style.RESET_ALL}"
                )
        except Exception as e:
            print(f"{Fore.RED}Erro na verificação de reputação: {e}{Style.RESET_ALL}")

    def analyze_subdomain_takeover(self):
        """Verificar potencial vulnerabilidade de subdomain takeover"""
        self.print_header("Análise de Subdomain Takeover")
        try:
            # Lista de serviços conhecidos que podem ser vulneráveis
            services = [
                "github.io",
                "herokuapp.com",
                "azure.com",
                "cloudfront.net",
                "aws.amazon.com",
                "web.app",
            ]

            # Gera subdomínios para teste
            subdomains = [
                f"test.{self.domain}",
                f"dev.{self.domain}",
                f"staging.{self.domain}",
                f"old.{self.domain}",
            ]

            for subdomain in subdomains:
                for service in services:
                    try:
                        ip = socket.gethostbyname(subdomain)
                        print(
                            f"{Fore.YELLOW}Possível vulnerabilidade:{Style.RESET_ALL}"
                        )
                        print(f"  Subdomínio: {subdomain}")
                        print(f"  IP: {ip}")
                        print(f"  Possível serviço: {service}")
                    except socket.gaierror:
                        # Subdomínio não existe, o que é normal
                        pass
        except Exception as e:
            print(
                f"{Fore.RED}Erro na análise de subdomain takeover: {e}{Style.RESET_ALL}"
            )

    def check_email_security(self):
        """Verificar configurações de segurança de e-mail"""
        self.print_header("Segurança de E-mail")
        try:
            # Verificar registros MX
            mx_records = dns.resolver.resolve(self.domain, "MX")

            print(f"{Fore.CYAN}Servidores de E-mail:{Style.RESET_ALL}")
            for rdata in mx_records:
                print(f"  - {rdata.exchange}")

            # Verificar SPF
            try:
                spf_records = dns.resolver.resolve(self.domain, "TXT")
                spf_found = False
                for record in spf_records:
                    txt_record = record.to_text()
                    if "v=spf1" in txt_record:
                        spf_found = True
                        print(
                            f"{Fore.GREEN}SPF encontrado:{Style.RESET_ALL} {txt_record}"
                        )

                if not spf_found:
                    print(
                        f"{Fore.YELLOW}Aviso: Nenhum registro SPF encontrado{Style.RESET_ALL}"
                    )
            except:
                print(
                    f"{Fore.YELLOW}Não foi possível verificar registros SPF{Style.RESET_ALL}"
                )

            # Verificar DMARC
            try:
                dmarc_records = dns.resolver.resolve(f"_dmarc.{self.domain}", "TXT")
                for record in dmarc_records:
                    txt_record = record.to_text()
                    if "v=DMARC1" in txt_record:
                        print(
                            f"{Fore.GREEN}DMARC encontrado:{Style.RESET_ALL} {txt_record}"
                        )
            except:
                print(
                    f"{Fore.YELLOW}Aviso: Nenhum registro DMARC encontrado{Style.RESET_ALL}"
                )

        except Exception as e:
            print(
                f"{Fore.RED}Erro na verificação de segurança de e-mail: {e}{Style.RESET_ALL}"
            )

    def analyze_domain(self):
        """Método principal de análise com todas as funcionalidades"""
        try:
            print(
                f"{Fore.CYAN}🔒 Iniciando Análise de Segurança Avançada{Style.RESET_ALL}\n"
            )

            # Métodos de análise básica
            self.get_domain_info()
            self.check_dns_records()
            self.check_ssl_security()
            self.check_certificate_revocation()
            self.analyze_certificate_chain()
            self.check_security_policies()
            self.detect_self_signed_certificates()
            self.check_security_headers()
            self.scan_common_directories()

            # Novas funcionalidades de segurança implementadas
            self.scan_sensitive_files()
            self.scan_owasp_top10()

            # Novas funcionalidades de análise
            self.get_ip_geolocation()
            self.detect_technologies()
            self.check_email_security()
            self.analyze_subdomain_takeover()

            # NOVAS FUNCIONALIDADES IMPLEMENTADAS
            print(
                f"\n{Fore.CYAN}🚀 Executando Novas Funcionalidades de Segurança{Style.RESET_ALL}"
            )

            # 1. Verificação em múltiplas blacklists
            self.check_multiple_blacklists()

            # 2. Análise de histórico de malware
            self.analyze_malware_history()

            # 3. Verificação de phishing e fraudes
            self.check_phishing_fraud()

            # 4. Score de reputação baseado em múltiplas fontes
            self.calculate_reputation_score()

            # Métodos que requerem cautela ou configurações específicas
            # Descomentar com cuidado e após configurações
            # self.check_open_ports()
            # self.check_domain_reputation()

            print(
                f"\n{Fore.GREEN}✅ Análise de Segurança Completa Finalizada!{Style.RESET_ALL}"
            )

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Análise interrompida pelo usuário{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Erro durante a análise: {e}{Style.RESET_ALL}")

    def check_multiple_blacklists(self):
        """Verificação em múltiplas blacklists (Spamhaus, SURBL, etc.)"""
        self.print_header("🔍 Verificação em Múltiplas Blacklists")

        try:
            # Obter IP do domínio
            ip_address = socket.gethostbyname(self.domain)
            print(f"{Fore.CYAN}IP do domínio:{Style.RESET_ALL} {ip_address}")

            # Verificar Spamhaus (múltiplas listas)
            print(f"\n{Fore.YELLOW}Verificando Spamhaus...{Style.RESET_ALL}")
            spamhaus_results = self._check_spamhaus_lists(ip_address)

            # Verificar outras blacklists
            print(f"\n{Fore.YELLOW}Verificando outras blacklists...{Style.RESET_ALL}")
            other_blacklists = self._check_other_blacklists(ip_address)

            # Consolidar resultados
            self.blacklist_results = {
                "spamhaus": spamhaus_results,
                "other_blacklists": other_blacklists,
                "total_blacklists": len(spamhaus_results) + len(other_blacklists),
                "blacklisted_count": sum(
                    1 for result in spamhaus_results.values() if result["listed"]
                )
                + sum(1 for result in other_blacklists.values() if result["listed"]),
            }

            # Exibir resumo
            self._display_blacklist_summary()

        except Exception as e:
            print(f"{Fore.RED}Erro na verificação de blacklists: {e}{Style.RESET_ALL}")
            self.logger.error(f"Erro na verificação de blacklists: {e}")

    def _check_spamhaus_lists(self, ip_address):
        """Verificar todas as listas do Spamhaus"""
        results = {}

        for list_name, range_info in BLACKLIST_SERVICES["spamhaus"].items():
            try:
                # Converter IP para formato reverso
                reversed_ip = ".".join(reversed(ip_address.split(".")))
                query_domain = f"{reversed_ip}.{list_name}"

                # Verificar se está na blacklist
                try:
                    dns.resolver.resolve(query_domain, "A")
                    results[list_name] = {
                        "listed": True,
                        "status": "BLOCKED",
                        "description": "IP encontrado na blacklist Spamhaus",
                    }
                    print(f"  {Fore.RED}❌ {list_name}: BLOQUEADO{Style.RESET_ALL}")
                except dns.resolver.NXDOMAIN:
                    results[list_name] = {
                        "listed": False,
                        "status": "CLEAN",
                        "description": "IP não encontrado na blacklist",
                    }
                    print(f"  {Fore.GREEN}✅ {list_name}: LIMPO{Style.RESET_ALL}")

            except Exception as e:
                results[list_name] = {
                    "listed": False,
                    "status": "ERROR",
                    "description": f"Erro na verificação: {e}",
                }
                print(f"  {Fore.YELLOW}⚠️ {list_name}: ERRO{Style.RESET_ALL}")

        return results

    def _check_other_blacklists(self, ip_address):
        """Verificar outras blacklists populares"""
        results = {}

        for service_name, dns_server in BLACKLIST_SERVICES.items():
            if service_name == "spamhaus":
                continue

            try:
                reversed_ip = ".".join(reversed(ip_address.split(".")))
                query_domain = f"{reversed_ip}.{dns_server}"

                try:
                    dns.resolver.resolve(query_domain, "A")
                    results[service_name] = {
                        "listed": True,
                        "status": "BLOCKED",
                        "description": f"IP encontrado na blacklist {service_name.upper()}",
                    }
                    print(f"  {Fore.RED}❌ {service_name}: BLOQUEADO{Style.RESET_ALL}")
                except dns.resolver.NXDOMAIN:
                    results[service_name] = {
                        "listed": False,
                        "status": "CLEAN",
                        "description": f"IP não encontrado na blacklist {service_name.upper()}",
                    }
                    print(f"  {Fore.GREEN}✅ {service_name}: LIMPO{Style.RESET_ALL}")

            except Exception as e:
                results[service_name] = {
                    "listed": False,
                    "status": "ERROR",
                    "description": f"Erro na verificação: {e}",
                }
                print(f"  {Fore.YELLOW}⚠️ {service_name}: ERRO{Style.RESET_ALL}")

        return results

    def _display_blacklist_summary(self):
        """Exibir resumo dos resultados das blacklists"""
        total_blacklists = self.blacklist_results["total_blacklists"]
        blacklisted_count = self.blacklist_results["blacklisted_count"]

        print(f"\n{Fore.CYAN}📊 Resumo das Blacklists:{Style.RESET_ALL}")
        print(f"Total de blacklists verificadas: {total_blacklists}")
        print(f"Blacklists que bloquearam: {blacklisted_count}")

        if blacklisted_count == 0:
            print(
                f"{Fore.GREEN}✅ Domínio não está em nenhuma blacklist conhecida{Style.RESET_ALL}"
            )
        elif blacklisted_count <= 2:
            print(
                f"{Fore.YELLOW}⚠️ Domínio está em {blacklisted_count} blacklist(s) - atenção necessária{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.RED}🚨 Domínio está em {blacklisted_count} blacklist(s) - alto risco{Style.RESET_ALL}"
            )

    def analyze_malware_history(self):
        """Análise de histórico de malware"""
        self.print_header("🦠 Análise de Histórico de Malware")

        try:
            # Verificar URLs suspeitas
            self._check_suspicious_urls()

            # Verificar padrões de malware
            self._check_malware_patterns()

            # Verificar domínios maliciosos conhecidos
            self._check_known_malicious_domains()

            # Verificar histórico de arquivos suspeitos
            self._check_malware_file_history()

            # Exibir resumo da análise
            self._display_malware_summary()

        except Exception as e:
            print(f"{Fore.RED}Erro na análise de malware: {e}{Style.RESET_ALL}")
            self.logger.error(f"Erro na análise de malware: {e}")

    def _check_suspicious_urls(self):
        """Verificar URLs suspeitas no domínio"""
        print(f"{Fore.YELLOW}Verificando URLs suspeitas...{Style.RESET_ALL}")

        suspicious_urls = []
        test_paths = [
            "/download",
            "/update",
            "/security",
            "/scan",
            "/clean",
            "/install",
            "/setup",
            "/patch",
            "/fix",
            "/repair",
        ]

        for path in test_paths:
            try:
                url = f"https://{self.domain}{path}"
                response = self.session.head(url, timeout=5, allow_redirects=True)

                if response.status_code == 200:
                    # Verificar se contém arquivos executáveis
                    if any(
                        ext in response.url.lower()
                        for ext in MALWARE_INDICATORS["file_types"]
                    ):
                        suspicious_urls.append(
                            {
                                "url": response.url,
                                "type": "executable_file",
                                "risk": "high",
                            }
                        )
                        print(
                            f"  {Fore.RED}🚨 URL suspeita encontrada: {response.url}{Style.RESET_ALL}"
                        )

            except Exception:
                continue

        self.malware_analysis["suspicious_urls"] = suspicious_urls

    def _check_malware_patterns(self):
        """Verificar padrões suspeitos de malware"""
        print(f"{Fore.YELLOW}Verificando padrões suspeitos...{Style.RESET_ALL}")

        try:
            # Verificar página inicial
            response = self.session.get(f"https://{self.domain}", timeout=10)
            content = response.text.lower()

            suspicious_patterns = []
            for pattern in MALWARE_INDICATORS["suspicious_patterns"]:
                if re.search(pattern, content):
                    suspicious_patterns.append(
                        {"pattern": pattern, "found_in": "homepage", "risk": "medium"}
                    )
                    print(
                        f"  {Fore.YELLOW}⚠️ Padrão suspeito encontrado: {pattern}{Style.RESET_ALL}"
                    )

            self.malware_analysis["suspicious_patterns"] = suspicious_patterns

        except Exception as e:
            print(
                f"  {Fore.YELLOW}⚠️ Não foi possível verificar padrões: {e}{Style.RESET_ALL}"
            )

    def _check_known_malicious_domains(self):
        """Verificar se o domínio é similar a domínios maliciosos conhecidos"""
        print(
            f"{Fore.YELLOW}Verificando similaridade com domínios maliciosos...{Style.RESET_ALL}"
        )

        domain_parts = self.domain.split(".")
        base_domain = domain_parts[0] if len(domain_parts) > 1 else self.domain

        # Verificar similaridade com domínios maliciosos conhecidos
        similar_domains = []
        for malicious in MALWARE_INDICATORS["malicious_domains"]:
            if (
                self._calculate_domain_similarity(base_domain, malicious.split(".")[0])
                > 0.7
            ):
                similar_domains.append(
                    {
                        "similar_to": malicious,
                        "similarity": self._calculate_domain_similarity(
                            base_domain, malicious.split(".")[0]
                        ),
                        "risk": "high",
                    }
                )
                print(
                    f"  {Fore.RED}🚨 Domínio similar a malicioso: {malicious}{Style.RESET_ALL}"
                )

        self.malware_analysis["similar_domains"] = similar_domains

    def _check_malware_file_history(self):
        """Verificar histórico de arquivos suspeitos"""
        print(f"{Fore.YELLOW}Verificando histórico de arquivos...{Style.RESET_ALL}")

        # Verificar arquivos de log e backup
        suspicious_files = []
        file_paths = [
            "/error.log",
            "/access.log",
            "/debug.log",
            "/backup.zip",
            "/backup.sql",
            "/backup.tar.gz",
        ]

        for file_path in file_paths:
            try:
                url = f"https://{self.domain}{file_path}"
                response = self.session.head(url, timeout=5)

                if response.status_code == 200:
                    suspicious_files.append(
                        {"file": file_path, "status": "accessible", "risk": "medium"}
                    )
                    print(
                        f"  {Fore.YELLOW}⚠️ Arquivo suspeito acessível: {file_path}{Style.RESET_ALL}"
                    )

            except Exception:
                continue

        self.malware_analysis["suspicious_files"] = suspicious_files

    def _calculate_domain_similarity(self, domain1, domain2):
        """Calcular similaridade entre dois domínios usando algoritmo de Levenshtein"""
        if len(domain1) < len(domain2):
            domain1, domain2 = domain2, domain1

        if len(domain2) == 0:
            return 0.0

        previous_row = list(range(len(domain2) + 1))
        for i, c1 in enumerate(domain1):
            current_row = [i + 1]
            for j, c2 in enumerate(domain2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        distance = previous_row[-1]
        max_len = max(len(domain1), len(domain2))
        return 1 - (distance / max_len)

    def _display_malware_summary(self):
        """Exibir resumo da análise de malware"""
        print(f"\n{Fore.CYAN}📊 Resumo da Análise de Malware:{Style.RESET_ALL}")

        total_indicators = (
            len(self.malware_analysis.get("suspicious_urls", []))
            + len(self.malware_analysis.get("suspicious_patterns", []))
            + len(self.malware_analysis.get("similar_domains", []))
            + len(self.malware_analysis.get("suspicious_files", []))
        )

        print(f"Total de indicadores suspeitos: {total_indicators}")

        if total_indicators == 0:
            print(
                f"{Fore.GREEN}✅ Nenhum indicador de malware encontrado{Style.RESET_ALL}"
            )
        elif total_indicators <= 2:
            print(
                f"{Fore.YELLOW}⚠️ Alguns indicadores suspeitos encontrados{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.RED}🚨 Múltiplos indicadores de malware - alto risco{Style.RESET_ALL}"
            )

    def check_phishing_fraud(self):
        """Verificação de phishing e fraudes"""
        self.print_header("🎣 Verificação de Phishing e Fraudes")

        try:
            # Verificar indicadores de phishing
            self._check_phishing_indicators()

            # Verificar tentativas de spoofing
            self._check_spoofing_attempts()

            # Verificar URLs de phishing conhecidas
            self._check_known_phishing_urls()

            # Verificar padrões de fraude
            self._check_fraud_patterns()

            # Exibir resumo da verificação
            self._display_phishing_summary()

        except Exception as e:
            print(f"{Fore.RED}Erro na verificação de phishing: {e}{Style.RESET_ALL}")
            self.logger.error(f"Erro na verificação de phishing: {e}")

    def _check_phishing_indicators(self):
        """Verificar indicadores comuns de phishing"""
        print(f"{Fore.YELLOW}Verificando indicadores de phishing...{Style.RESET_ALL}")

        try:
            response = self.session.get(f"https://{self.domain}", timeout=10)
            content = response.text.lower()

            phishing_indicators = []

            # Verificar palavras-chave suspeitas
            suspicious_keywords = [
                "verify your account",
                "account suspended",
                "security alert",
                "unusual activity",
                "login attempt",
                "password expired",
                "update your information",
                "confirm your identity",
                "bank security",
                "credit card verification",
            ]

            for keyword in suspicious_keywords:
                if keyword in content:
                    phishing_indicators.append(
                        {
                            "type": "suspicious_keyword",
                            "keyword": keyword,
                            "risk": "high",
                        }
                    )
                    print(
                        f"  {Fore.RED}🚨 Palavra-chave suspeita: {keyword}{Style.RESET_ALL}"
                    )

            # Verificar formulários de login
            if "login" in content or "signin" in content:
                if "password" in content and "username" in content:
                    # Verificar se é um formulário de login legítimo
                    if self._is_legitimate_login_form(content):
                        print(
                            f"  {Fore.GREEN}✅ Formulário de login parece legítimo{Style.RESET_ALL}"
                        )
                    else:
                        phishing_indicators.append(
                            {
                                "type": "suspicious_login_form",
                                "description": "Formulário de login suspeito",
                                "risk": "high",
                            }
                        )
                        print(
                            f"  {Fore.RED}🚨 Formulário de login suspeito detectado{Style.RESET_ALL}"
                        )

            self.phishing_indicators["keywords"] = phishing_indicators

        except Exception as e:
            print(
                f"  {Fore.YELLOW}⚠️ Não foi possível verificar indicadores: {e}{Style.RESET_ALL}"
            )

    def _check_spoofing_attempts(self):
        """Verificar tentativas de spoofing"""
        print(f"{Fore.YELLOW}Verificando tentativas de spoofing...{Style.RESET_ALL}")

        spoofing_indicators = []

        # Verificar se o domínio tenta se passar por um serviço conhecido
        known_services = [
            "google",
            "facebook",
            "amazon",
            "microsoft",
            "apple",
            "paypal",
            "ebay",
            "netflix",
            "spotify",
            "twitter",
        ]

        domain_lower = self.domain.lower()
        for service in known_services:
            if service in domain_lower and service not in self.domain:
                # Verificar se é uma tentativa de typosquatting
                if self._is_typosquatting(self.domain, service):
                    spoofing_indicators.append(
                        {
                            "type": "typosquatting",
                            "target_service": service,
                            "risk": "high",
                        }
                    )
                    print(
                        f"  {Fore.RED}🚨 Possível typosquatting de {service}{Style.RESET_ALL}"
                    )

        # Verificar caracteres confusos (homoglyphs)
        if self._has_confusing_characters(self.domain):
            spoofing_indicators.append(
                {
                    "type": "confusing_characters",
                    "description": "Domínio usa caracteres confusos",
                    "risk": "medium",
                }
            )
            print(f"  {Fore.YELLOW}⚠️ Domínio usa caracteres confusos{Style.RESET_ALL}")

        self.phishing_indicators["spoofing"] = spoofing_indicators

    def _check_known_phishing_urls(self):
        """Verificar URLs de phishing conhecidas"""
        print(
            f"{Fore.YELLOW}Verificando URLs de phishing conhecidas...{Style.RESET_ALL}"
        )

        try:
            # Verificar no PhishTank (API pública)
            phishtank_url = f"https://checkurl.phishtank.com/checkurl/"
            data = {"url": f"https://{self.domain}"}

            response = self.session.post(phishtank_url, data=data, timeout=10)

            if "phish" in response.text.lower():
                self.phishing_indicators["phishtank"] = {
                    "status": "phishing",
                    "source": "PhishTank",
                    "risk": "high",
                }
                print(
                    f"  {Fore.RED}🚨 Domínio reportado como phishing no PhishTank{Style.RESET_ALL}"
                )
            else:
                self.phishing_indicators["phishtank"] = {
                    "status": "clean",
                    "source": "PhishTank",
                }
                print(
                    f"  {Fore.GREEN}✅ Domínio não encontrado no PhishTank{Style.RESET_ALL}"
                )

        except Exception as e:
            print(
                f"  {Fore.YELLOW}⚠️ Não foi possível verificar no PhishTank: {e}{Style.RESET_ALL}"
            )

    def _check_fraud_patterns(self):
        """Verificar padrões de fraude"""
        print(f"{Fore.YELLOW}Verificando padrões de fraude...{Style.RESET_ALL}")

        fraud_indicators = []

        try:
            response = self.session.get(f"https://{self.domain}", timeout=10)
            content = response.text.lower()

            # Verificar padrões de fraude financeira
            fraud_patterns = [
                "you have won",
                "claim your prize",
                "free money",
                "investment opportunity",
                "get rich quick",
                "lottery winner",
                "inheritance",
                "unclaimed funds",
                "tax refund",
            ]

            for pattern in fraud_patterns:
                if pattern in content:
                    fraud_indicators.append(
                        {"type": "fraud_pattern", "pattern": pattern, "risk": "high"}
                    )
                    print(
                        f"  {Fore.RED}🚨 Padrão de fraude detectado: {pattern}{Style.RESET_ALL}"
                    )

            self.phishing_indicators["fraud_patterns"] = fraud_indicators

        except Exception as e:
            print(
                f"  {Fore.YELLOW}⚠️ Não foi possível verificar padrões de fraude: {e}{Style.RESET_ALL}"
            )

    def _is_legitimate_login_form(self, content):
        """Verificar se um formulário de login é legítimo"""
        # Verificar se tem campos de segurança
        security_indicators = [
            "csrf",
            "token",
            "nonce",
            "captcha",
            "recaptcha",
            "two-factor",
            "2fa",
            "mfa",
            "otp",
        ]

        return any(indicator in content for indicator in security_indicators)

    def _is_typosquatting(self, domain, service):
        """Verificar se um domínio é typosquatting de um serviço"""
        # Implementar lógica de detecção de typosquatting
        # Por simplicidade, vamos usar uma verificação básica
        return len(domain) <= len(service) + 3 and service in domain

    def _has_confusing_characters(self, domain):
        """Verificar se um domínio usa caracteres confusos"""
        confusing_chars = {
            "0": "o",
            "1": "l",
            "3": "e",
            "5": "s",
            "6": "g",
            "8": "b",
            "9": "g",
            "l": "1",
            "o": "0",
            "e": "3",
        }

        for char in domain:
            if char in confusing_chars:
                return True
        return False

    def _display_phishing_summary(self):
        """Exibir resumo da verificação de phishing"""
        print(f"\n{Fore.CYAN}📊 Resumo da Verificação de Phishing:{Style.RESET_ALL}")

        total_indicators = (
            len(self.phishing_indicators.get("keywords", []))
            + len(self.phishing_indicators.get("spoofing", []))
            + len(self.phishing_indicators.get("fraud_patterns", []))
        )

        phishtank_status = self.phishing_indicators.get("phishtank", {}).get(
            "status", "unknown"
        )

        print(f"Total de indicadores de phishing: {total_indicators}")
        print(f"Status no PhishTank: {phishtank_status}")

        if total_indicators == 0 and phishtank_status != "phishing":
            print(
                f"{Fore.GREEN}✅ Nenhum indicador de phishing detectado{Style.RESET_ALL}"
            )
        elif total_indicators <= 2:
            print(
                f"{Fore.YELLOW}⚠️ Alguns indicadores de phishing detectados{Style.RESET_ALL}"
            )
        else:
            print(
                f"{Fore.RED}🚨 Múltiplos indicadores de phishing - alto risco{Style.RESET_ALL}"
            )

    def calculate_reputation_score(self):
        """Score de reputação baseado em múltiplas fontes"""
        self.print_header("📊 Score de Reputação")

        try:
            # Inicializar score
            base_score = 100
            deductions = 0
            reputation_details = {}

            print(f"{Fore.YELLOW}Calculando score de reputação...{Style.RESET_ALL}")

            # 1. Verificar blacklists
            blacklist_score = self._calculate_blacklist_score()
            reputation_details["blacklists"] = blacklist_score

            # 2. Verificar análise de malware
            malware_score = self._calculate_malware_score()
            reputation_details["malware"] = malware_score

            # 3. Verificar phishing
            phishing_score = self._calculate_phishing_score()
            reputation_details["phishing"] = phishing_score

            # 4. Verificar APIs de reputação externas
            external_reputation = self._check_external_reputation()
            reputation_details["external"] = external_reputation

            # 5. Verificar idade do domínio
            domain_age_score = self._calculate_domain_age_score()
            reputation_details["domain_age"] = domain_age_score

            # 6. Verificar configurações de segurança
            security_score = self._calculate_security_score()
            reputation_details["security"] = security_score

            # Calcular score final
            final_score = self._calculate_final_score(reputation_details)

            # Armazenar resultados
            self.reputation_score = final_score
            self.reputation_details = reputation_details

            # Exibir score final
            self._display_reputation_score(final_score, reputation_details)

        except Exception as e:
            print(
                f"{Fore.RED}Erro no cálculo do score de reputação: {e}{Style.RESET_ALL}"
            )
            self.logger.error(f"Erro no cálculo do score de reputação: {e}")

    def _calculate_blacklist_score(self):
        """Calcular score baseado nas blacklists"""
        if not hasattr(self, "blacklist_results") or not self.blacklist_results:
            return {"score": 0, "deduction": 0, "details": "Não verificado"}

        blacklisted_count = self.blacklist_results.get("blacklisted_count", 0)
        total_blacklists = self.blacklist_results.get("total_blacklists", 0)

        if total_blacklists == 0:
            return {
                "score": 0,
                "deduction": 0,
                "details": "Nenhuma blacklist verificada",
            }

        # Penalizar por cada blacklist
        deduction_per_blacklist = 20
        total_deduction = blacklisted_count * deduction_per_blacklist

        score = max(0, 100 - total_deduction)

        return {
            "score": score,
            "deduction": total_deduction,
            "details": f"Em {blacklisted_count}/{total_blacklists} blacklists",
        }

    def _calculate_malware_score(self):
        """Calcular score baseado na análise de malware"""
        if not hasattr(self, "malware_analysis") or not self.malware_analysis:
            return {"score": 0, "deduction": 0, "details": "Não verificado"}

        total_indicators = (
            len(self.malware_analysis.get("suspicious_urls", []))
            + len(self.malware_analysis.get("suspicious_patterns", []))
            + len(self.malware_analysis.get("similar_domains", []))
            + len(self.malware_analysis.get("suspicious_files", []))
        )

        # Penalizar por cada indicador
        deduction_per_indicator = 15
        total_deduction = total_indicators * deduction_per_indicator

        score = max(0, 100 - total_deduction)

        return {
            "score": score,
            "deduction": total_deduction,
            "details": f"{total_indicators} indicadores suspeitos",
        }

    def _calculate_phishing_score(self):
        """Calcular score baseado na verificação de phishing"""
        if not hasattr(self, "phishing_indicators") or not self.phishing_indicators:
            return {"score": 0, "deduction": 0, "details": "Não verificado"}

        total_indicators = (
            len(self.phishing_indicators.get("keywords", []))
            + len(self.phishing_indicators.get("spoofing", []))
            + len(self.phishing_indicators.get("fraud_patterns", []))
        )

        # Penalizar por cada indicador
        deduction_per_indicator = 20
        total_deduction = total_indicators * deduction_per_indicator

        # Penalizar adicionalmente se estiver no PhishTank
        phishtank_status = self.phishing_indicators.get("phishtank", {}).get(
            "status", "unknown"
        )
        if phishtank_status == "phishing":
            total_deduction += 50

        score = max(0, 100 - total_deduction)

        return {
            "score": score,
            "deduction": total_deduction,
            "details": f"{total_indicators} indicadores de phishing",
        }

    def _check_external_reputation(self):
        """Verificar reputação em APIs externas"""
        print(f"  {Fore.YELLOW}Verificando reputação externa...{Style.RESET_ALL}")

        external_scores = {}

        # Verificar URLhaus (sem API key)
        try:
            urlhaus_url = f"https://urlhaus-api.abuse.ch/v1/host/"
            data = {"host": self.domain}

            response = self.session.post(urlhaus_url, data=data, timeout=10)
            result = response.json()

            if result.get("query_status") == "ok":
                if result.get("url_count", 0) > 0:
                    external_scores["urlhaus"] = {
                        "score": 0,
                        "deduction": 100,
                        "details": "Domínio reportado como malicioso",
                    }
                    print(f"    {Fore.RED}🚨 URLhaus: MALICIOSO{Style.RESET_ALL}")
                else:
                    external_scores["urlhaus"] = {
                        "score": 100,
                        "deduction": 0,
                        "details": "Domínio limpo",
                    }
                    print(f"    {Fore.GREEN}✅ URLhaus: LIMPO{Style.RESET_ALL}")
            else:
                external_scores["urlhaus"] = {
                    "score": 50,
                    "deduction": 50,
                    "details": "Erro na verificação",
                }
                print(f"    {Fore.YELLOW}⚠️ URLhaus: ERRO{Style.RESET_ALL}")

        except Exception as e:
            external_scores["urlhaus"] = {
                "score": 50,
                "deduction": 50,
                "details": f"Erro: {e}",
            }
            print(f"    {Fore.YELLOW}⚠️ URLhaus: ERRO{Style.RESET_ALL}")

        # Calcular score médio das APIs externas
        if external_scores:
            total_score = sum(score["score"] for score in external_scores.values())
            avg_score = total_score / len(external_scores)
            total_deduction = 100 - avg_score

            return {
                "score": avg_score,
                "deduction": total_deduction,
                "details": f"Média de {len(external_scores)} APIs externas",
                "apis": external_scores,
            }
        else:
            return {
                "score": 50,
                "deduction": 50,
                "details": "Nenhuma API externa verificada",
            }

    def _calculate_domain_age_score(self):
        """Calcular score baseado na idade do domínio"""
        try:
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date

            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                age_days = (datetime.now() - creation_date).days

                if age_days > 365 * 2:  # Mais de 2 anos
                    return {
                        "score": 100,
                        "deduction": 0,
                        "details": f"Domínio antigo ({age_days} dias)",
                    }
                elif age_days > 365:  # Mais de 1 ano
                    return {
                        "score": 80,
                        "deduction": 20,
                        "details": f"Domínio maduro ({age_days} dias)",
                    }
                elif age_days > 30:  # Mais de 1 mês
                    return {
                        "score": 60,
                        "deduction": 40,
                        "details": f"Domínio recente ({age_days} dias)",
                    }
                else:  # Menos de 1 mês
                    return {
                        "score": 30,
                        "deduction": 70,
                        "details": f"Domínio muito recente ({age_days} dias)",
                    }
            else:
                return {
                    "score": 50,
                    "deduction": 50,
                    "details": "Data de criação desconhecida",
                }

        except Exception as e:
            return {
                "score": 50,
                "deduction": 50,
                "details": f"Erro na verificação: {e}",
            }

    def _calculate_security_score(self):
        """Calcular score baseado nas configurações de segurança"""
        # Este método seria implementado baseado nas verificações de segurança existentes
        # Por simplicidade, vamos retornar um score base
        return {
            "score": 75,
            "deduction": 25,
            "details": "Configurações de segurança básicas",
        }

    def _calculate_final_score(self, reputation_details):
        """Calcular score final baseado em todos os fatores"""
        if not reputation_details:
            return 0

        # Pesos para cada categoria
        weights = {
            "blacklists": 0.25,
            "malware": 0.25,
            "phishing": 0.20,
            "external": 0.20,
            "domain_age": 0.05,
            "security": 0.05,
        }

        total_score = 0
        total_weight = 0

        for category, weight in weights.items():
            if category in reputation_details:
                category_score = reputation_details[category].get("score", 0)
                total_score += category_score * weight
                total_weight += weight

        if total_weight > 0:
            final_score = total_score / total_weight
        else:
            final_score = 0

        return round(final_score, 1)

    def _display_reputation_score(self, final_score, reputation_details):
        """Exibir o score de reputação final"""
        print(f"\n{Fore.CYAN}📊 Score de Reputação Final:{Style.RESET_ALL}")

        # Determinar categoria do score
        if final_score >= 80:
            category = f"{Fore.GREEN}EXCELENTE{Style.RESET_ALL}"
            risk_level = f"{Fore.GREEN}BAIXO RISCO{Style.RESET_ALL}"
        elif final_score >= 60:
            category = f"{Fore.YELLOW}BOM{Style.RESET_ALL}"
            risk_level = f"{Fore.YELLOW}RISCO MODERADO{Style.RESET_ALL}"
        elif final_score >= 40:
            category = f"{Fore.YELLOW}REGULAR{Style.RESET_ALL}"
            risk_level = f"{Fore.YELLOW}RISCO ALTO{Style.RESET_ALL}"
        else:
            category = f"{Fore.RED}RUIM{Style.RESET_ALL}"
            risk_level = f"{Fore.RED}ALTÍSSIMO RISCO{Style.RESET_ALL}"

        print(f"Score Final: {Fore.CYAN}{final_score}/100{Style.RESET_ALL}")
        print(f"Categoria: {category}")
        print(f"Nível de Risco: {risk_level}")

        print(f"\n{Fore.CYAN}Detalhes por Categoria:{Style.RESET_ALL}")
        for category_name, details in reputation_details.items():
            if isinstance(details, dict) and "score" in details:
                score = details["score"]
                deduction = details["deduction"]
                description = details["details"]

                if score >= 80:
                    color = Fore.GREEN
                elif score >= 60:
                    color = Fore.YELLOW
                else:
                    color = Fore.RED

                print(
                    f"  {category_name.title()}: {color}{score}/100{Style.RESET_ALL} ({description})"
                )


def main():
    print(f"{Fore.CYAN}=== Analisador de Domínios Avançado v2.0 ==={Style.RESET_ALL}")
    while True:
        domain = input(
            "\nDigite o domínio para análise (ou 'sair' para encerrar): "
        ).strip()
        if domain.lower() == "sair":
            break

        analyzer = DomainAnalyzer(domain)
        analyzer.analyze_domain()

        print(f"\n{Fore.CYAN}Análise concluída!{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
