import os
import pytest

from app import app, init_db, get_db


@pytest.fixture
def client(tmp_path):
    # Usar um banco TEMPORÁRIO para os testes
    app.config["TESTING"] = True
    test_db_path = os.path.join(tmp_path, "test.db")
    app.config["DATABASE"] = test_db_path

    with app.test_client() as client:
        with app.app_context():
            init_db()  # cria as tabelas no banco de teste
        yield client
        # Não precisa dropar, o arquivo some com o tmp_path


def login(client, username="professor", password="1234"):
    return client.post(
        "/",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def test_index_page_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Login do Professor" in resp.data


def test_login_success(client):
    resp = login(client)
    assert resp.status_code == 200
    # Depois do login, cai em /students
    assert b"Cadastrar Estudante" in resp.data


def test_login_fail(client):
    resp = login(client, username="x", password="y")
    assert b"Usuario ou senha invalidos" in resp.data or \
           b"Usuario ou senha" in resp.data


def test_create_student_and_grade(client):
    # Faz login
    login(client)

    # Cria estudante
    resp = client.post(
        "/estudantes",
        data={
            "nome": "Aluno Teste",
            "matricula": "123",
            "email": "aluno@teste.com",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Estudante cadastrado com sucesso" in resp.data

    # Busca o estudante no banco
    with app.app_context():
        db = get_db()
        cadastro = db.execute(
            "SELECT id, nome FROM cadastro WHERE matricula = ?",
            ("123",),
        ).fetchone()
        assert cadastro is not None
        id_estudante = cadastro["id"]

    # Lança nota
    resp = client.post(
        "/notas",
        data={
            "id_estudante": id_estudante,
            "disciplina": "Matemática",
            "nota": "9.5",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Nota lan" in resp.data  # pega começo de "lançada"

    # Verifica se a nota aparece na tabela
    assert b"Notas lan" in resp.data
    assert b"Matem" in resp.data  # parte de "Matemática"
