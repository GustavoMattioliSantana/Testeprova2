import os
import sys
import pytest
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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

def login(client, username="admin", password="admin123", follow=True):
    return client.post(
        "/",
        data={"username": username, "password": password},
        follow_redirects=follow,
    )

def test_login_fail(client):
    resp = login(client, username="x", password="y")
    text = resp.get_data(as_text=True)
    assert "Usuário ou senha inválidos" in text or "Usuário ou senha" in text

def test_index_page_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    text = resp.get_data(as_text=True)
    assert "Login" in text  # verifica que a página de login carrega

def test_login_success(client):
    resp = login(client)
    text = resp.get_data(as_text=True)
    # o app faz flash de sucesso e redireciona para /admin (usuário padrão admin)
    assert resp.status_code == 200
    assert "Login realizado com sucesso" in text

def test_create_student_and_grade(client):
    # 1) Faz login como admin (usuário padrão criado em init_db)
    resp = login(client)
    assert resp.status_code == 200

    # 2) Cria estudante (rota /estudantes — exige role=admin)
    resp = client.post(
        "/estudantes",
        data={
            "nome": "Aluno Teste",
            "matricula": "123",
            "email": "aluno@teste.com",
        },
        follow_redirects=True,
    )
    text = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "Estudante cadastrado com sucesso" in text

    # 3) Cria um usuário professor via /admin (admin cria professor)
    resp = client.post(
        "/admin",
        data={
            "nome": "Prof Teste",
            "username": "prof_teste",
            "password": "prof123",
            "role": "professor",
            "disciplina": "Matemática",
        },
        follow_redirects=True,
    )
    text = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "criado com sucesso" in text  # verifica criação do usuário

    # 4) Busca o estudante no banco para obter o id
    with app.app_context():
        db = get_db()
        cadastro = db.execute(
            "SELECT id, nome FROM cadastro WHERE matricula = ?",
            ("123",),
        ).fetchone()
        assert cadastro is not None
        id_estudante = cadastro["id"]

    # 5) Faz logout e login como professor
    client.get("/logout", follow_redirects=True)
    resp = login(client, username="prof_teste", password="prof123")
    text = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "Login realizado com sucesso" in text

    # 6) Professor lança nota para o estudante
    resp = client.post(
        "/notas",
        data={
            "id_estudante": id_estudante,
            "nota": "9.5",
        },
        follow_redirects=True,
    )
    text = resp.get_data(as_text=True)
    assert resp.status_code == 200