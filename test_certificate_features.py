#!/usr/bin/env python3
"""
Teste das novas funcionalidades de certificados SSL/TLS
Implementadas no Explorador DNS Avançado

Funcionalidades testadas:
1. Verificação de certificados revogados (CRL/OCSP)
2. Análise de cadeia de certificados
3. Verificação de políticas de segurança (HSTS, CSP)
4. Detecção de certificados auto-assinados ou inválidos
"""

import sys
import os

# Adicionar o diretório atual ao path para importar o módulo principal
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Importar diretamente do arquivo
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Importar a classe do arquivo principal
exec(open("explorador-dns.py").read())


def test_certificate_features():
    """Testa as novas funcionalidades de certificados"""
    print("🔒 Testando Novas Funcionalidades de Certificados SSL/TLS\n")

    # Domínios de teste (alguns com diferentes configurações de segurança)
    test_domains = [
        "google.com",  # Domínio com boa segurança
        "github.com",  # Domínio com HSTS e CSP
        "example.com",  # Domínio básico
    ]

    for domain in test_domains:
        print(f"🌐 Testando domínio: {domain}")
        print("=" * 60)

        try:
            analyzer = DomainAnalyzer(domain)

            # Testar apenas as funcionalidades de certificados
            print("\n1️⃣ Verificação de Revogação de Certificados:")
            analyzer.check_certificate_revocation()

            print("\n2️⃣ Análise da Cadeia de Certificados:")
            analyzer.analyze_certificate_chain()

            print("\n3️⃣ Verificação de Políticas de Segurança:")
            analyzer.check_security_policies()

            print("\n4️⃣ Detecção de Certificados Auto-assinados:")
            analyzer.detect_self_signed_certificates()

        except Exception as e:
            print(f"❌ Erro ao testar {domain}: {e}")

        print("\n" + "=" * 60 + "\n")


def test_specific_domain():
    """Testa um domínio específico fornecido pelo usuário"""
    domain = input("Digite o domínio para teste específico: ").strip()

    if not domain:
        print("❌ Domínio não fornecido")
        return

    try:
        analyzer = DomainAnalyzer(domain)

        print(f"\n🔒 Testando funcionalidades de certificados para: {domain}\n")

        # Executar todas as verificações de certificados
        analyzer.check_certificate_revocation()
        analyzer.analyze_certificate_chain()
        analyzer.check_security_policies()
        analyzer.detect_self_signed_certificates()

    except Exception as e:
        print(f"❌ Erro durante o teste: {e}")


def main():
    """Menu principal de teste"""
    print("🔒 Testador de Funcionalidades de Certificados SSL/TLS")
    print("=" * 60)

    while True:
        print("\nOpções:")
        print("1. Testar domínios predefinidos")
        print("2. Testar domínio específico")
        print("3. Sair")

        choice = input("\nEscolha uma opção (1-3): ").strip()

        if choice == "1":
            test_certificate_features()
        elif choice == "2":
            test_specific_domain()
        elif choice == "3":
            print("👋 Saindo do testador...")
            break
        else:
            print("❌ Opção inválida. Tente novamente.")


if __name__ == "__main__":
    main()
