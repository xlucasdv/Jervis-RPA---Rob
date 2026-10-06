# Inclusão de novas plataformas

Exemplo: incluir o **Veeam Backup Enterprise Manager** (tipo `veeam`). Os passos são os mesmos para qualquer
plataforma web com login e listas em tabela. Use os coletores existentes como referência: `acronis.py` é o mais
próximo de uma ferramenta de backup; `zabbix.py` mostra cruzamento entre conjuntos e leitura de cores.

## 1. Perfil de login — `src/jervis/auth/profiles.py`

```python
PROFILES = {
    ...,
    "veeam": LoginProfile(
        username=("#username", "input[name='username']"),
        password=("#password", "input[type='password']"),
        submit=("button[type='submit']",),
        error=(".login-error", "[role='alert']"),
        success=(".main-menu",),
        success_url=(r"/(home|dashboard)",),
    ),
}
```

O tipo passa a ser aceito no arquivo de configuração automaticamente (`SUPPORTED_KINDS`). Valide o login antes de
seguir: `jervis platforms add veeam --kind veeam --url https://...`, `jervis credentials set veeam`,
`jervis login veeam --headed`.

## 2. Coletor — `src/jervis/collectors/veeam.py`

```python
from jervis.collectors.base import Collector, DatasetSpec
from jervis.collectors.parsing import parse_datetime, to_iso
from jervis.collectors.table import TableSpec

JOB_COLUMNS = {
    "nome_tarefa": ("Job", "Nome", "Name"),
    "status_backup": ("Status", "Resultado", "Result"),
    "ultima_execucao": ("Última execução", "Last run"),
}


class VeeamCollector(Collector):
    kind = "veeam"

    def default_datasets(self) -> dict[str, DatasetSpec]:
        return {
            "tarefas": DatasetSpec(
                name="tarefas",
                pages={"job": "/em/jobs"},              # relativo à URL após o login
                table=TableSpec(columns=JOB_COLUMNS, required=("nome_tarefa", "status_backup")),
                normalize=self._normalize_job,
            ),
        }

    def _normalize_job(self, row):
        when = parse_datetime(row.get("ultima_execucao"), order=self.date_order)
        return {**row, "ultima_execucao_iso": to_iso(when)}
```

- `required`: sem essas colunas a página falha como `interface_alterada`; as demais ausentes geram aviso;
  `extras` são silenciosas.
- Para colunas cujo valor está na cor (como a disponibilidade do Zabbix), use `class_fields` e leia
  `_<campo>_classes` no normalizador.
- Parâmetros próprios (como `max_age_hours`): `option_names` + `configure()`.
- Destaques e cruzamentos entre conjuntos: `summarize(result)`.

Registre em `src/jervis/collectors/__init__.py`:

```python
COLLECTORS = {..., VeeamCollector.kind: VeeamCollector}
```

## 3. Consolidação — `src/jervis/consolidation/rules.py`

Sem esta etapa os dados aparecem nos JSON da coleta, mas não no consolidado nem nos relatórios (ficam listados
em "Conjuntos sem regra de consolidação").

```python
def veeam_task(row, ctx):
    failed = matches(row.get("status_backup"), ("failed", "falha", "error"))
    return record(
        ctx, BACKUP_TASK, row.get("nome_tarefa"), CRITICAL if failed else NORMAL,
        status=row.get("status_backup"), data_evento=row.get("ultima_execucao_iso"),
        data_original=row.get("ultima_execucao"),
    )

MAPPERS[("veeam", "tarefas")] = veeam_task
```

Reaproveite as categorias existentes (`BACKUP_TASK`, `HOST`...) sempre que fizer sentido: o resumo executivo
conta "backups com falha", "dispositivos" e "alertas" por categoria. Categoria nova: inclua-a em
`consolidation/model.py` e o rótulo em `reports/data.py` (`CATEGORY_LABEL`).

## 4. Relatórios — `src/jervis/reports/data.py`

```python
PLATFORM_LABEL = {..., "veeam": "Veeam Backup"}
```

Se os indicadores executivos dependem do novo tipo (ex.: "backups com falha" vindo também do Veeam), revise
`executive_summary()` e `_coverage()`.

## 5. Modelo de configuração — `src/jervis/templates/platforms.example.yaml`

Inclua um bloco comentado da nova plataforma (URL de exemplo, MFA, `params` mais comuns).

## 6. Testes

1. **Página falsa** em `tests/fixtures/site/veeam/`, imitando a estrutura real (cabeçalhos, paginação,
   carregamento). Reaproveite `tests/fixtures/site/common/table.js` para listas paginadas.
2. **Unitários** (`tests/test_veeam_unit.py`): normalização, classificação, validação de `params`.
3. **Navegação** (`tests/test_veeam_browser.py`, marcados `browser`): coleta completa contra a página falsa,
   interface alterada, lista vazia.
4. **Consolidação**: um caso em `tests/test_consolidation.py` para a regra nova.

```powershell
.venv\Scripts\python -m pytest -q tests/test_veeam_unit.py tests/test_veeam_browser.py
.venv\Scripts\python -m pytest -q                       # suíte completa antes de entregar
```

## 7. Validação no ambiente real

```powershell
jervis check veeam --headed --screenshots      # login, páginas e colunas
jervis collect veeam
jervis report --open
```

## Checklist

- [ ] Perfil de login em `profiles.py` e login validado com `jervis login --headed`
- [ ] Coletor com conjuntos, colunas (PT e EN) e normalização; registrado em `COLLECTORS`
- [ ] Regras de consolidação em `MAPPERS`; categorias e rótulos de relatório
- [ ] Bloco no modelo de configuração
- [ ] Página falsa, testes unitários, de navegação e de consolidação
- [ ] `jervis check` OK no ambiente real
- [ ] Documentação: seção em [plataformas.md](plataformas.md)
