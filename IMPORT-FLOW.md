# Importação no Financeiro — formato do arquivo

O Evolve Flow exporta um **arquivo JSON** (botão "⬇ Arquivo p/ Financeiro") com os
dados do cliente para a ferramenta financeira importar. Use JSON (não o PDF) para
importar — é 100% confiável; ler PDF é frágil e quebra fácil.

## Nome do arquivo
`financeiro-<empresa>.json` (ex: `financeiro-casa-das-rodas.json`)

## Estrutura — versão 2 (chaves estáveis, não mudam sem alinhar os dois lados)

```json
{
  "tipo": "evolve_flow_cliente_financeiro",
  "versao": 2,
  "clienteId": "k3f9a2b1c",
  "empresa": "Casa das Rodas",
  "razaoSocial": "Casa das Rodas LTDA",
  "cnpj": "00.000.000/0001-00",
  "enderecoFiscal": "Rua X, 123 - Cidade/UF",
  "responsavelFinanceiro": "Fulano",
  "emailFinanceiro": "financeiro@cliente.com",
  "telefoneFinanceiro": "(51) 90000-0000",
  "valorContrato": "2000",
  "diaVencimento": "30",
  "inicioContrato": "2026-09",
  "fimContrato": "",
  "tipoCobranca": "recorrente",
  "orcamentoMidia": "1500",
  "servicos": ["Meta Ads", "Google Ads"],
  "descricaoSugerida": "Mensalidade Casa das Rodas",
  "categoriaSugerida": "Anúncios",
  "exportadoEm": "2026-08-09T20:00:00.000Z"
}
```

## O que mudou da versão 1 para a 2

| v1 | v2 | Motivo |
|---|---|---|
| — | `clienteId` | Chave estável de idempotência. Reimportar atualiza em vez de duplicar. |
| `prazo` (texto livre) | `inicioContrato` + `fimContrato` | "3 meses" não dá para calcular com segurança. Competência `AAAA-MM` dá. |
| — | `tipoCobranca` | `recorrente` (todo mês) ou `pontual` (uma vez só). |
| `vencimento` (texto) | `diaVencimento` (número 1–31) | Alimenta a data no Fluxo de caixa; número é confiável, frase não. |

## Campos obrigatórios

O Flow **recusa exportar** sem `empresa`, `valorContrato` e `inicioContrato`.
O Financeiro **recusa importar** o arquivo inteiro se faltar qualquer um deles,
se `fimContrato` vier antes de `inicioContrato`, ou se `tipo` não for
`evolve_flow_cliente_financeiro`. Nunca grava pela metade.

## Como o Financeiro trata

O cliente vira uma **recorrência de receita** (`recurring_items`), não um
lançamento avulso. A partir daí os lançamentos são gerados em todos os meses da
vigência, e MRR, Fluxo de caixa e Projeção passam a considerar sozinhos.

- `fimContrato` preenchido faz o cliente sair do MRR a partir do mês seguinte
  ao fim — inclusive nos meses projetados à frente, não só no atual.
- `tipoCobranca: "pontual"` é gravado como vigência de um mês só.
- A chave de idempotência é `clienteId`; se vier vazio, cai para CNPJ, depois
  e-mail, depois nome da empresa, nessa ordem.

Endpoint: `POST /api/import/flow-cliente` no Evolve Financeiro.
Tela: menu lateral → **Importar do Flow**.
