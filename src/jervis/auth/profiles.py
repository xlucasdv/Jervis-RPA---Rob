"""Perfis de login: seletores CSS usados para automatizar cada plataforma.

Cada campo aceita uma lista de seletores candidatos; o primeiro elemento
*visível* encontrado é utilizado. Assim um mesmo perfil cobre variações de
versão/layout das plataformas.

IMPORTANTE: os seletores padrão abaixo são um ponto de partida e devem ser
validados contra o ambiente real (versão do Zabbix, datacenter da Acronis,
fluxo de login da Sophos). Qualquer campo pode ser sobrescrito por plataforma
na chave ``selectors`` do arquivo de configuração, sem alterar o código.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from typing import Mapping


@dataclass(frozen=True)
class LoginProfile:
    username: tuple[str, ...]
    password: tuple[str, ...]
    submit: tuple[str, ...]
    # Botão "Avançar" de fluxos em duas etapas (usuário → senha). Se vazio, usa ``submit``.
    next: tuple[str, ...] = ()
    # Elementos que, visíveis e com texto, indicam falha de autenticação.
    error: tuple[str, ...] = ()
    mfa_input: tuple[str, ...] = ()
    mfa_submit: tuple[str, ...] = ()
    # Login bem-sucedido: algum elemento visível OU URL casando com alguma regex.
    success: tuple[str, ...] = ()
    success_url: tuple[str, ...] = ()

    def with_overrides(self, overrides: Mapping[str, list[str]]) -> LoginProfile:
        return replace(self, **{key: tuple(value) for key, value in overrides.items()})


SELECTOR_FIELDS: tuple[str, ...] = tuple(f.name for f in fields(LoginProfile))

_GENERIC_ERRORS = ("[role='alert']", ".alert-danger", ".error-message")

PROFILES: dict[str, LoginProfile] = {
    # Sophos Central: login via Sophos ID (Azure AD B2C). Sophos Central exige MFA.
    "sophos": LoginProfile(
        username=("#signInName", "#email", "input[type='email']", "input[name='username']"),
        password=("#password", "input[type='password']"),
        submit=("#next", "button[type='submit']"),
        error=(".error.pageLevel", ".error.itemLevel", *_GENERIC_ERRORS),
        mfa_input=(
            "#otpCode",
            "#verificationCode",
            "input[autocomplete='one-time-code']",
            "input[name='otp']",
            "input[name='code']",
        ),
        mfa_submit=("#next", "#verifyCode", "button[type='submit']"),
        success_url=(r"^https://[^/]*central\.sophos\.com/manage/(?!login)",),
    ),
    # Acronis Cyber Protect Cloud: login em duas etapas (login → Avançar → senha).
    "acronis": LoginProfile(
        # Tela real (br02-cloud, 2026): input[name='username'] visível + cópias ocultas com o mesmo nome,
        # ignoradas porque só campos visíveis são usados.
        username=("input[name='username']", "input[name='login']", "#login", "input[type='email']"),
        password=("input[name='password']", "input[type='password']"),
        submit=("button[type='submit']",),
        next=("button[type='submit']",),
        error=(".el-form-item__error", ".acv-alert-danger", *_GENERIC_ERRORS),
        # Tela real (/totp): campo numérico único para os 6 dígitos.
        mfa_input=("input.el-totp-code-native", "input[name='totp']", "input[name='code']",
                   "input[autocomplete='one-time-code']"),
        mfa_submit=("button[type='submit']",),
        success_url=(r"^https?://[^/]+/(ui|mc|services)/",),
    ),
    # Zabbix 5.x–7.x (frontend PHP padrão).
    "zabbix": LoginProfile(
        username=("#name", "input[name='name']"),
        password=("#password", "input[name='password']"),
        submit=("#enter", "button[type='submit']"),
        error=(".signin-container .red", "div.red", ".msg-bad"),
        mfa_input=("#verification_code", "input[name='verification_code']"),
        mfa_submit=("button[type='submit']", "#enter"),
        success=("aside.sidebar", ".sidebar", ".icon-signout", ".zi-sign-out"),
        success_url=(r"zabbix\.php\?action=",),
    ),
}

SUPPORTED_KINDS: tuple[str, ...] = tuple(PROFILES)
