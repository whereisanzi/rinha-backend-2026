# rinha-backend-2026

Submissão para a [Rinha de Backend 2026 — Detecção de fraude por busca vetorial](https://github.com/zanfranceschi/rinha-de-backend-2026).

- **Branch `main`** — código-fonte.
- **Branch `submission`** — apenas os artefatos necessários para o teste oficial (`docker-compose.yml` na raiz).

## Restrições da rinha

- 1 CPU e 350 MB de memória somando todos os serviços
- Load balancer + 2 instâncias da API mínimo
- `POST /fraud-score` e `GET /ready` na porta 9999
- Imagens públicas `linux-amd64`, modo de rede `bridge`
