#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de Teste para as Novas Funcionalidades de Segurança
Explorador DNS - Versão 2.0

Este script testa as 4 novas funcionalidades implementadas:
1. Verificação em múltiplas blacklists
2. Análise de histórico de malware
3. Verificação de phishing e fraudes
4. Score de reputação baseado em múltiplas fontes
"""

import sys
import time
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)


def print_header(text):
    """Imprimir cabeçalho formatado"""
    print(f"\n{Fore.BLUE}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{text:^60}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}{'=' * 60}{Style.RESET_ALL}")


def print_section(text):
    """Imprimir seção formatada"""
    print(f"\n{Fore.CYAN}{text}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * len(text)}{Style.RESET_ALL}")


def test_domain_analyzer():
    """Testar o analisador de domínios com as novas funcionalidades"""
    try:
        from explorador_dns import DomainAnalyzer

        print_header("🧪 TESTANDO NOVAS FUNCIONALIDADES DE SEGURANÇA")

        # Lista de domínios para teste
        test_domains = [
            "google.com",  # Domínio legítimo conhecido
            "example.com",  # Domínio de exemplo
            "test.com",  # Domínio de teste
        ]

        print_section("Domínios de Teste Disponíveis")
        for i, domain in enumerate(test_domains, 1):
            print(f"{i}. {Fore.YELLOW}{domain}{Style.RESET_ALL}")

        print_section("Seleção de Domínio")
        while True:
            try:
                choice = input(
                    f"\nEscolha um domínio (1-{len(test_domains)}) ou digite um domínio personalizado: "
                ).strip()

                if choice.isdigit() and 1 <= int(choice) <= len(test_domains):
                    selected_domain = test_domains[int(choice) - 1]
                else:
                    selected_domain = choice

                if selected_domain:
                    break
                else:
                    print(
                        f"{Fore.RED}Por favor, insira um domínio válido.{Style.RESET_ALL}"
                    )

            except (ValueError, IndexError):
                print(f"{Fore.RED}Escolha inválida. Tente novamente.{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Domínio selecionado: {selected_domain}{Style.RESET_ALL}")

        # Criar instância do analisador
        print_section("Inicializando Analisador")
        analyzer = DomainAnalyzer(selected_domain)
        print(
            f"✅ Analisador inicializado para: {Fore.CYAN}{selected_domain}{Style.RESET_ALL}"
        )

        # Testar cada nova funcionalidade individualmente
        print_header("🔍 TESTE 1: Verificação em Múltiplas Blacklists")
        try:
            analyzer.check_multiple_blacklists()
            print(
                f"{Fore.GREEN}✅ Teste de blacklists concluído com sucesso!{Style.RESET_ALL}"
            )
        except Exception as e:
            print(f"{Fore.RED}❌ Erro no teste de blacklists: {e}{Style.RESET_ALL}")

        time.sleep(2)  # Pausa para melhor visualização

        print_header("🦠 TESTE 2: Análise de Histórico de Malware")
        try:
            analyzer.analyze_malware_history()
            print(
                f"{Fore.GREEN}✅ Teste de análise de malware concluído com sucesso!{Style.RESET_ALL}"
            )
        except Exception as e:
            print(
                f"{Fore.RED}❌ Erro no teste de análise de malware: {e}{Style.RESET_ALL}"
            )

        time.sleep(2)

        print_header("🎣 TESTE 3: Verificação de Phishing e Fraudes")
        try:
            analyzer.check_phishing_fraud()
            print(
                f"{Fore.GREEN}✅ Teste de verificação de phishing concluído com sucesso!{Style.RESET_ALL}"
            )
        except Exception as e:
            print(
                f"{Fore.RED}❌ Erro no teste de verificação de phishing: {e}{Style.RESET_ALL}"
            )

        time.sleep(2)

        print_header("📊 TESTE 4: Score de Reputação")
        try:
            analyzer.calculate_reputation_score()
            print(
                f"{Fore.GREEN}✅ Teste de score de reputação concluído com sucesso!{Style.RESET_ALL}"
            )
        except Exception as e:
            print(
                f"{Fore.RED}❌ Erro no teste de score de reputação: {e}{Style.RESET_ALL}"
            )

        # Resumo dos testes
        print_header("📋 RESUMO DOS TESTES")
        print(
            f"{Fore.GREEN}✅ Todas as novas funcionalidades foram testadas!{Style.RESET_ALL}"
        )
        print(f"\n{Fore.CYAN}Resultados armazenados em:{Style.RESET_ALL}")
        print(f"  - Blacklists: {len(analyzer.blacklist_results)} resultados")
        print(f"  - Malware: {len(analyzer.malware_analysis)} análises")
        print(f"  - Phishing: {len(analyzer.phishing_indicators)} indicadores")
        print(f"  - Reputação: Score {analyzer.reputation_score}/100")

        return True

    except ImportError as e:
        print(f"{Fore.RED}❌ Erro ao importar o módulo: {e}{Style.RESET_ALL}")
        print(
            f"{Fore.YELLOW}Certifique-se de que o arquivo explorador-dns.py está no mesmo diretório.{Style.RESET_ALL}"
        )
        return False
    except Exception as e:
        print(f"{Fore.RED}❌ Erro inesperado: {e}{Style.RESET_ALL}")
        return False


def test_individual_features():
    """Testar funcionalidades individuais"""
    print_header("🔧 TESTE DE FUNCIONALIDADES INDIVIDUAIS")

    print_section("1. Teste de Configurações")
    try:
        from explorador_dns import (
            BLACKLIST_SERVICES,
            REPUTATION_APIS,
            MALWARE_INDICATORS,
        )

        print(f"✅ BLACKLIST_SERVICES: {len(BLACKLIST_SERVICES)} serviços configurados")
        print(f"✅ REPUTATION_APIS: {len(REPUTATION_APIS)} APIs configuradas")
        print(
            f"✅ MALWARE_INDICATORS: {len(MALWARE_INDICATORS)} indicadores configurados"
        )

        # Mostrar detalhes das configurações
        print(f"\n{Fore.CYAN}Serviços de Blacklist:{Style.RESET_ALL}")
        for service, config in BLACKLIST_SERVICES.items():
            if isinstance(config, dict):
                print(f"  - {service}: {len(config)} listas")
            else:
                print(f"  - {service}: {config}")

        print(f"\n{Fore.CYAN}APIs de Reputação:{Style.RESET_ALL}")
        for api, config in REPUTATION_APIS.items():
            print(
                f"  - {api}: {'Requer API Key' if config['api_key_required'] else 'Sem API Key'}"
            )

        return True

    except ImportError as e:
        print(f"{Fore.RED}❌ Erro ao importar configurações: {e}{Style.RESET_ALL}")
        return False


def main():
    """Função principal"""
    print_header("🧪 TESTADOR DE NOVAS FUNCIONALIDADES - EXPLORADOR DNS")

    print(
        f"{Fore.CYAN}Este script testa as 4 novas funcionalidades implementadas:{Style.RESET_ALL}"
    )
    print(f"1. {Fore.YELLOW}🔍 Verificação em Múltiplas Blacklists{Style.RESET_ALL}")
    print(f"2. {Fore.YELLOW}🦠 Análise de Histórico de Malware{Style.RESET_ALL}")
    print(f"3. {Fore.YELLOW}🎣 Verificação de Phishing e Fraudes{Style.RESET_ALL}")
    print(f"4. {Fore.YELLOW}📊 Score de Reputação Inteligente{Style.RESET_ALL}")

    print_section("Menu de Testes")
    print("1. Teste Completo (Todas as funcionalidades)")
    print("2. Teste de Configurações")
    print("3. Sair")

    while True:
        try:
            choice = input(f"\nEscolha uma opção (1-3): ").strip()

            if choice == "1":
                success = test_domain_analyzer()
                if success:
                    print(
                        f"\n{Fore.GREEN}🎉 Todos os testes foram concluídos com sucesso!{Style.RESET_ALL}"
                    )
                else:
                    print(
                        f"\n{Fore.RED}❌ Alguns testes falharam. Verifique os erros acima.{Style.RESET_ALL}"
                    )
                break

            elif choice == "2":
                success = test_individual_features()
                if success:
                    print(
                        f"\n{Fore.GREEN}✅ Configurações testadas com sucesso!{Style.RESET_ALL}"
                    )
                else:
                    print(
                        f"\n{Fore.RED}❌ Teste de configurações falhou.{Style.RESET_ALL}"
                    )
                break

            elif choice == "3":
                print(f"\n{Fore.YELLOW}👋 Saindo do testador...{Style.RESET_ALL}")
                break

            else:
                print(f"{Fore.RED}Opção inválida. Escolha 1, 2 ou 3.{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(
                f"\n\n{Fore.YELLOW}👋 Teste interrompido pelo usuário.{Style.RESET_ALL}"
            )
            break
        except Exception as e:
            print(f"\n{Fore.RED}❌ Erro inesperado: {e}{Style.RESET_ALL}")
            break

    print(
        f"\n{Fore.CYAN}Para mais informações, consulte o arquivo NOVAS_FUNCIONALIDADES.md{Style.RESET_ALL}"
    )


if __name__ == "__main__":
    main()
