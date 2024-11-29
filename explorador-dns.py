import socket
import whois
import dns.resolver
import requests
import ssl
import json
import concurrent.futures
from urllib.parse import urljoin
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

# Bibliotecas para geolocalização e reputação
import geoip2.database
import tldextract

# Inicializa colorama para formatação colorida
init()

# Configuration and logging setup
init(autoreset=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('domain_analysis.log', mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)

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
            'timeout': 10,
            'max_workers': 10,
            'reputation_apis': [
                'https://www.virustotal.com/vtapi/v2/url/report',
                'https://urlhaus-api.abuse.ch/v1/host/',
                'https://api.malsir.com/v1/lookup'
            ],
            'security_threshold': 0.3,
            'common_ports': [21, 22, 80, 443, 3306, 8080, 5432]
        }

# Desativa avisos de SSL não verificado
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class DomainAnalyzer:
    def __init__(self, domain):
        self.domain = self.clean_domain(domain)
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Carregar banco de dados de geolocalização
        try:
            self.geoip_reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
        except FileNotFoundError:
            print(f"{Fore.YELLOW}Aviso: Banco de dados GeoLite2 não encontrado. Geolocalização desativada.{Style.RESET_ALL}")
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
                print(f"{Fore.CYAN}Registrador:{Style.RESET_ALL} {domain_info.registrar}")
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    print(f"{Fore.CYAN}Data de Criação:{Style.RESET_ALL} {domain_info.creation_date[0]}")
                else:
                    print(f"{Fore.CYAN}Data de Criação:{Style.RESET_ALL} {domain_info.creation_date}")
            if domain_info.expiration_date:
                if isinstance(domain_info.expiration_date, list):
                    print(f"{Fore.CYAN}Data de Expiração:{Style.RESET_ALL} {domain_info.expiration_date[0]}")
                else:
                    print(f"{Fore.CYAN}Data de Expiração:{Style.RESET_ALL} {domain_info.expiration_date}")
            if domain_info.name_servers:
                print(f"{Fore.CYAN}Servidores DNS:{Style.RESET_ALL}")
                for ns in domain_info.name_servers:
                    print(f"  - {ns}")
        except Exception as e:
            print(f"{Fore.RED}Erro ao obter informações WHOIS: {e}{Style.RESET_ALL}")

    def check_dns_records(self):
        self.print_header("Registros DNS")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                print(f"\n{Fore.CYAN}Registros {record_type}:{Style.RESET_ALL}")
                for rdata in answers:
                    if record_type == 'MX':
                        print(f"  Prioridade: {rdata.preference} Servidor: {rdata.exchange}")
                    elif record_type == 'SOA':
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
                print(f"{Fore.RED}Erro ao verificar registro {record_type}: {e}{Style.RESET_ALL}")

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
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    
                    print(f"\n{Fore.CYAN}Informações do Certificado:{Style.RESET_ALL}")
                    print(f"Válido desde: {not_before}")
                    print(f"Válido até: {not_after}")
                    
                    # Verificar status de validade
                    now = datetime.now()
                    if now < not_after:
                        days_remaining = (not_after - now).days
                        print(f"{Fore.GREEN}Certificado válido (Dias restantes: {days_remaining}){Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}ALERTA: Certificado expirado!{Style.RESET_ALL}")
                    
                    # Subject Alternative Names (SANs)
                    if 'subjectAltName' in cert:
                        print(f"\n{Fore.CYAN}SANs:{Style.RESET_ALL}")
                        for type_name, value in cert['subjectAltName']:
                            print(f"  {type_name}: {value}")
                    
                    # Informações do emissor
                    if 'issuer' in cert:
                        print(f"\n{Fore.CYAN}Emissor:{Style.RESET_ALL}")
                        for attr in cert['issuer']:
                            print(f"  {attr[0][0]}: {attr[0][1]}")
        except Exception as e:
            print(f"{Fore.RED}Erro na análise SSL: {e}{Style.RESET_ALL}")

    def check_security_headers(self):
        self.print_header("Cabeçalhos de Segurança")
        try:
            response = self.session.get(f"https://{self.domain}", verify=False, timeout=10)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'X-Frame',
                'X-Content-Type-Options': 'X-Content-Type',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy',
                'Server': 'Server'
            }
            
            for header, description in security_headers.items():
                value = headers.get(header)
                if value:
                    print(f"{Fore.CYAN}{description}:{Style.RESET_ALL} {value}")
                else:
                    print(f"{Fore.YELLOW}Aviso: {description} não configurado{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}Erro ao verificar cabeçalhos: {e}{Style.RESET_ALL}")

    def scan_common_directories(self):
        self.print_header("Varredura de Diretórios")
        common_dirs = [
            'admin', 'wp-admin', 'administrator', 'login', 'wp-login.php',
            'backup', 'db', 'database', 'dev', 'development',
            'test', 'testing', 'staging', 'prod', 'production',
            'api', 'v1', 'v2', 'api-docs', 'swagger',
            'phpinfo.php', 'phpmyadmin', 'mysql', 'config',
            '.git', '.env', '.htaccess', 'robots.txt', 'sitemap.xml'
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
                            print(f"{Fore.GREEN}Encontrado:{Style.RESET_ALL} {url} (Status: {status})")
                        elif status in [301, 302, 403]:
                            print(f"{Fore.YELLOW}Restrito:{Style.RESET_ALL} {url} (Status: {status})")
                except Exception as e:
                    continue

    def check_directory(self, url):
        try:
            response = self.session.get(url, verify=False, timeout=5, allow_redirects=False)
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
                    print(f"{Fore.CYAN}Código do País:{Style.RESET_ALL} {response.country.iso_code}")
                except:
                    print(f"{Fore.YELLOW}Não foi possível obter informações geográficas detalhadas{Style.RESET_ALL}")
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
                state = result['scan'][self.domain]['tcp'][port]['state']
                service = result['scan'][self.domain]['tcp'][port].get('name', 'Desconhecido')
                
                if state == 'open':
                    print(f"{Fore.GREEN}Porta {port} aberta:{Style.RESET_ALL} {service}")
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
            if 'X-Powered-By' in headers:
                technologies.append(f"Powered By: {headers['X-Powered-By']}")
            if 'Server' in headers:
                technologies.append(f"Servidor: {headers['Server']}")
            
            # Detecção por conteúdo
            content = response.text.lower()
            web_techs = {
                'WordPress': 'wp-content' in content,
                'Joomla': 'joomla' in content,
                'Drupal': 'drupal' in content,
                'React': 'react' in content,
                'Angular': 'ng-app' in content,
                'Vue.js': 'vue' in content,
                'Bootstrap': 'bootstrap' in content,
                'jQuery': 'jquery' in content
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

    def check_domain_reputation(self):
        """Verificar reputação básica do domínio"""
        self.print_header("Reputação do Domínio")
        try:
            api_key = 'f93bc98d8ddc3c5d2444ee2e8397382d2e3a2ccea0fd383ed02a12e0f36c0345'
            url = f'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': api_key, 'resource': f"http://{self.domain}"}
            
            response = requests.get(url, params=params)
            if response.status_code == 200:
                result = response.json()
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                
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
                print(f"{Fore.YELLOW}Não foi possível verificar a reputação{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Erro na verificação de reputação: {e}{Style.RESET_ALL}")

    def analyze_subdomain_takeover(self):
        """Verificar potencial vulnerabilidade de subdomain takeover"""
        self.print_header("Análise de Subdomain Takeover")
        try:
            # Lista de serviços conhecidos que podem ser vulneráveis
            services = [
                'github.io', 'herokuapp.com', 'azure.com', 
                'cloudfront.net', 'aws.amazon.com', 'web.app'
            ]
            
            # Gera subdomínios para teste
            subdomains = [
                f'test.{self.domain}',
                f'dev.{self.domain}',
                f'staging.{self.domain}',
                f'old.{self.domain}'
            ]
            
            for subdomain in subdomains:
                for service in services:
                    try:
                        ip = socket.gethostbyname(subdomain)
                        print(f"{Fore.YELLOW}Possível vulnerabilidade:{Style.RESET_ALL}")
                        print(f"  Subdomínio: {subdomain}")
                        print(f"  IP: {ip}")
                        print(f"  Possível serviço: {service}")
                    except socket.gaierror:
                        # Subdomínio não existe, o que é normal
                        pass
        except Exception as e:
            print(f"{Fore.RED}Erro na análise de subdomain takeover: {e}{Style.RESET_ALL}")

    def check_email_security(self):
        """Verificar configurações de segurança de e-mail"""
        self.print_header("Segurança de E-mail")
        try:
            # Verificar registros MX
            mx_records = dns.resolver.resolve(self.domain, 'MX')
            
            print(f"{Fore.CYAN}Servidores de E-mail:{Style.RESET_ALL}")
            for rdata in mx_records:
                print(f"  - {rdata.exchange}")
            
            # Verificar SPF
            try:
                spf_records = dns.resolver.resolve(self.domain, 'TXT')
                spf_found = False
                for record in spf_records:
                    txt_record = record.to_text()
                    if 'v=spf1' in txt_record:
                        spf_found = True
                        print(f"{Fore.GREEN}SPF encontrado:{Style.RESET_ALL} {txt_record}")
                
                if not spf_found:
                    print(f"{Fore.YELLOW}Aviso: Nenhum registro SPF encontrado{Style.RESET_ALL}")
            except:
                print(f"{Fore.YELLOW}Não foi possível verificar registros SPF{Style.RESET_ALL}")
            
            # Verificar DMARC
            try:
                dmarc_records = dns.resolver.resolve(f"_dmarc.{self.domain}", 'TXT')
                for record in dmarc_records:
                    txt_record = record.to_text()
                    if 'v=DMARC1' in txt_record:
                        print(f"{Fore.GREEN}DMARC encontrado:{Style.RESET_ALL} {txt_record}")
            except:
                print(f"{Fore.YELLOW}Aviso: Nenhum registro DMARC encontrado{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}Erro na verificação de segurança de e-mail: {e}{Style.RESET_ALL}")

    def analyze_domain(self):
        """Método principal de análise com todas as funcionalidades"""
        try:
            # Métodos de análise básica
            self.get_domain_info()
            self.check_dns_records()
            self.check_ssl_security()
            self.check_security_headers()
            self.scan_common_directories()
            
            # Novas funcionalidades de análise
            self.get_ip_geolocation()
            self.detect_technologies()
            self.check_email_security()
            self.analyze_subdomain_takeover()
            
            # Métodos que requerem cautela ou configurações específicas
            # Descomentar com cuidado e após configurações
            # self.check_open_ports()
            # self.check_domain_reputation()
        
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Análise interrompida pelo usuário{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}Erro durante a análise: {e}{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}=== Analisador de Domínios Avançado v2.0 ==={Style.RESET_ALL}")
    while True:
        domain = input("\nDigite o domínio para análise (ou 'sair' para encerrar): ").strip()
        if domain.lower() == 'sair':
            break
        
        analyzer = DomainAnalyzer(domain)
        analyzer.analyze_domain()
        
        print(f"\n{Fore.CYAN}Análise concluída!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()