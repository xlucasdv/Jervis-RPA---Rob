"""Exceções da aplicação.

As mensagens são exibidas diretamente ao operador: devem ser claras, indicar a
próxima ação e nunca conter segredos.
"""

from enum import StrEnum


class JervisError(Exception):
    """Erro base da aplicação."""


class ConfigError(JervisError):
    """Configuração ausente ou inválida."""


class CredentialError(JervisError):
    """Falha ao ler ou gravar credenciais."""


class CredentialsNotFoundError(CredentialError):
    """Nenhuma credencial cadastrada para a plataforma."""


class BrowserError(JervisError):
    """Não foi possível iniciar o navegador."""


class PlatformUnavailableError(JervisError):
    """A plataforma não pôde ser acessada (rede, DNS, certificado...)."""


class AuthenticationError(JervisError):
    """Falha genérica de autenticação em uma plataforma."""

    def __init__(self, platform: str, message: str):
        self.platform = platform
        self.message = message
        super().__init__(f"[{platform}] {message}")


class AccessDeniedError(AuthenticationError):
    """A plataforma recusou as credenciais."""


class MfaRequiredError(AuthenticationError):
    """A plataforma exige MFA, mas a ferramenta não tem como fornecer o código."""


class MfaFailedError(AuthenticationError):
    """O código MFA foi recusado ou não pôde ser gerado."""


class LoginTimeoutError(AuthenticationError):
    """A plataforma não respondeu como esperado dentro do tempo limite."""


class IssueCategory(StrEnum):
    """Classificação das falhas registradas durante a coleta."""

    AUTHENTICATION = "autenticacao"
    UNAVAILABLE = "indisponibilidade"
    NAVIGATION = "navegacao"
    UI_CHANGED = "interface_alterada"
    TIMEOUT = "tempo_esgotado"
    CONFIGURATION = "configuracao"
    INCOMPLETE_DATA = "dados_incompletos"
    UNEXPECTED = "inesperado"


class CollectionError(JervisError):
    """Falha em uma etapa da coleta. ``retryable`` indica se vale tentar de novo."""

    category = IssueCategory.UNEXPECTED
    retryable = False

    def __init__(self, message: str, category: IssueCategory | None = None, retryable: bool | None = None):
        super().__init__(message)
        if category is not None:
            self.category = category
        if retryable is not None:
            self.retryable = retryable


class NavigationError(CollectionError):
    """Não foi possível abrir a página da plataforma."""

    category = IssueCategory.NAVIGATION
    retryable = True


class SessionExpiredError(CollectionError):
    """A plataforma voltou para a tela de login durante a coleta."""

    category = IssueCategory.AUTHENTICATION


class UiChangedError(CollectionError):
    """A página não tem a estrutura esperada (tabela, colunas): a interface provavelmente mudou."""

    category = IssueCategory.UI_CHANGED


class CollectionTimeoutError(CollectionError):
    """A página não terminou de carregar dentro do tempo limite."""

    category = IssueCategory.TIMEOUT
    retryable = True
