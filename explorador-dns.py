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
import socket
import nmap
import requests
import json
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

# Inicializa colorama para formatação colorida
init()

# Configuration and logging setup
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s: %(message)s",
    handlers=[
        logging.FileHandler("domain_analysis.log", mode="a"),
        logging.StreamHandler(sys.stdout),
    ],
)

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
