# Sistema de Lançamento de Notas — Flask + SQLite + CI/CD

Um projeto educacional que simula um **sistema escolar de lançamento de notas**, desenvolvido em **Python (Flask)** e **HTML**, com **persistência em SQLite**, **testes automatizados com Pytest**, **containerização com Docker** e **integração contínua via GitHub Actions**.

---

## 📘 Sumário

* [Visão Geral](#-visão-geral)
* [Estrutura do Projeto](#-estrutura-do-projeto)
* [Tecnologias Utilizadas](#️-tecnologias-utilizadas)
* [Funcionalidades](#-funcionalidades)
* [Instalação e Execução Local](#-instalação-e-execução-local)
* [Testes Automatizados](#-testes-automatizados)
* [🐳 Execução com Docker](#-execução-com-docker)
* [Integração Contínua (CI/CD)](#-integração-contínua-cicd)
* [Estrutura de Diretórios](#-estrutura-de-diretórios)


---

## 🚀 Visão Geral

Este projeto tem como objetivo **ensinar boas práticas de desenvolvimento backend e DevOps** a partir de um exemplo prático e completo.

O sistema permite que um **professor faça login**, **cadastre estudantes** e **registre notas por disciplina**, armazenando tudo em um banco **SQLite local**.
A aplicação está configurada para ser **testada automaticamente** e **executada dentro de containers Docker**, com **pipelines automatizados no GitHub Actions**.

---

## Estrutura do Projeto

```
backend-devops/
├── app.py                     # Aplicação principal Flask
├── requirements.txt           # Dependências do projeto
├── Dockerfile                 # Containerização da aplicação
├── pytest.ini                 # Configuração do Pytest
├── testes/
│   └── teste.py            # Testes automatizados
├── templates/
│   ├── base.html              # Layout base (Bootstrap)
│   ├── index.html             # Página de login
│   ├── estudantes.html        # Cadastro de estudantes
│   └── notas.html             # Lançamento de notas
├── .github/
│   └── workflows/
│       └── ci.yml             # Pipeline de CI/CD (GitHub Actions)
├── .gitignore                 # Arquivos a serem ignorados
└── README.md                  # Este arquivo 😊
```

---

## Tecnologias Utilizadas

| Categoria           | Tecnologias           |
| ------------------- | --------------------- |
| **Linguagem**       | Python 3.11           |
| **Framework Web**   | Flask                 |
| **Banco de Dados**  | SQLite                |
| **Testes**          | Pytest + Pytest-Flask |
| **Containerização** | Docker                |
| **CI/CD**           | GitHub Actions        |
| **Front-End**       | HTML5 + Bootstrap 5   |

---

## Funcionalidades

✅ Login de professor com sessão e autenticação simples
✅ Cadastro de estudantes (nome, matrícula, e-mail)
✅ Lançamento de notas por disciplina
✅ Listagem de notas e estudantes cadastrados
✅ Persistência em banco SQLite
✅ Logout seguro com limpeza de sessão e cookie
✅ Testes automatizados (login, cadastro, notas)
✅ Execução isolada com Docker
✅ Integração contínua no GitHub (CI/CD)

---

## Instalação e Execução Local

### 1️⃣ Clonar o repositório

```bash
git clone https://github.com/rgcavallari/backend-devops.git
cd sistema-notas
```

### 2️⃣ Criar e ativar o ambiente virtual

```bash
python -m venv venv
source venv/bin/activate   # Linux / Mac
venv\Scripts\activate      # Windows
```

### 3️⃣ Instalar as dependências

```bash
pip install -r requirements.txt
```

### 4️⃣ Executar o aplicativo

```bash
python app.py
```

Acesse http://127.0.0.1:5000/

> **Login padrão:**
> Usuário: `professor`
> Senha: `1234`

---

## Testes Automatizados

Para rodar os testes localmente:

```bash
pytest -v
```

Os testes verificam:

* Login com credenciais corretas/incorretas
* Cadastro de estudante
* Lançamento de nota
* Persistência de dados no banco temporário

---

## 🐳 Execução com Docker

### 1️⃣ Construir a imagem

```bash
docker build -t sistema-notas .
```

### 2️⃣ Rodar o container

```bash
docker run -p 5000:5000 sistema-notas
```

Acesse novamente em [http://localhost:5000](http://localhost:5000)

---

## Integração Contínua (CI/CD)

O projeto inclui um workflow do **GitHub Actions** que roda automaticamente a cada *push*:

```yaml
on: [push, pull_request]

jobs:
  test-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r requirements.txt
      - run: pytest

  test-docker:
    runs-on: ubuntu-latest
    needs: test-python
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t sistema-notas-ci .
      - run: docker run --rm sistema-notas-ci pytest
```

✅ Executa testes Python
✅ Faz build Docker
✅ Roda testes dentro do container
✅ Garante que o código só é aprovado se tudo passar

---

## Estrutura de Diretórios

| Pasta / Arquivo            | Descrição               |
| -------------------------- | ----------------------- |
| `app.py`                   | Código principal Flask  |
| `templates/`               | Páginas HTML (views)    |
| `testes/`                  | Testes automatizados    |
| `.github/workflows/ci.yml` | Pipeline CI/CD          |
| `Dockerfile`               | Container da aplicação  |
| `requirements.txt`         | Dependências do Python  |
| `.gitignore`               | Exclusões do Git        |
| `README.md`                | Documentação do projeto |

---
