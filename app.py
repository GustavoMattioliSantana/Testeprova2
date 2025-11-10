import os
import sqlite3
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g
)
from functools import wraps

app = Flask(__name__)

# Chave de sessão (para login simples)
app.config["SECRET_KEY"] = "chave-secreta-super-simples"

# Caminho do banco SQLite
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["DATABASE"] = os.path.join(BASE_DIR, "escola.db")

# Usuário de login fixo (para simplificar)
USUARIO_PROF = "professor"
SENHA_PROF = "1234"

def get_db():
    """Abre uma conexão com o banco SQLite e guarda em g.db."""
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row  # permite acessar colunas por nome
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Fecha a conexão ao final da requisição."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Cria as tabelas se ainda não existirem."""
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS cadastro (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            matricula TEXT NOT NULL UNIQUE,
            email TEXT UNIQUE
        );
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS notas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            id_estudante INTEGER NOT NULL,
            disciplina TEXT NOT NULL,
            nota REAL NOT NULL,
            FOREIGN KEY (id_estudante) REFERENCES cadastro (id)
        );
        """
    )
    db.commit()


@app.before_request
def create_tables():
    init_db()

#Verificação de segurança
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            flash("Faça login para acessar esta página.")
            return redirect(url_for("index"))
        return view_func(*args, **kwargs)
    return wrapper

#validação de usuário
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == USUARIO_PROF and password == SENHA_PROF:
            session["usuario"] = username
            return redirect(url_for("estudantes"))
        else:
            flash("Usuario ou senha invalidos.", "danger")

    return render_template("index.html")


@app.route("/logout")
def logout():
    # Limpa toda a sessão
    session.clear()
    # Cria resposta de redirecionamento
    response = redirect(url_for("index"))
    # Remove cookie de sessão do navegador (força expiração)
    response.set_cookie("session", "", expires=0)

    flash("Você saiu do sistema.", "info")
    return response


@app.route("/estudantes", methods=["GET", "POST"])
@login_required
def estudantes():
    db = get_db()

    if request.method == "POST":
        nome = request.form.get("nome")
        matricula = request.form.get("matricula")
        email = request.form.get("email")

        if not nome or not matricula:
            flash("Nome e matrícula são obrigatórios.")
        else:
            try:
                db.execute(
                    "INSERT INTO cadastro (nome, matricula, email) VALUES (?, ?, ?)",
                    (nome, matricula, email),
                )
                db.commit()
                flash("Estudante cadastrado com sucesso!")
            except sqlite3.IntegrityError as e:
                # erro típico de UNIQUE (matricula / email repetido)
                flash(f"Erro ao cadastrar estudante (dados duplicados?): {e}")
            except Exception as e:
                flash(f"Erro ao cadastrar estudante: {e}")

    estudantes = db.execute("SELECT id, nome, matricula, email FROM cadastro").fetchall()
    return render_template("estudantes.html", estudantes=estudantes)


@app.route("/notas", methods=["GET", "POST"])
@login_required
def notas():
    db = get_db()

    # Para o formulário de lançamento de notas
    estudantes = db.execute(
        "SELECT id, nome, matricula FROM cadastro"
    ).fetchall()

    if request.method == "POST":
        id_estudante = request.form.get("id_estudante")
        disciplina = request.form.get("disciplina")
        nota = request.form.get("nota")

        if not id_estudante or not disciplina or not nota:
            flash("Todos os campos são obrigatórios.")
        else:
            try:
                nota_valor = float(nota)
                db.execute(
                    "INSERT INTO notas (id_estudante, disciplina, nota) VALUES (?, ?, ?)",
                    (id_estudante, disciplina, nota_valor),
                )
                db.commit()
                flash("Nota lançada com sucesso!")
            except ValueError:
                flash("Nota deve ser numérica.")
            except Exception as e:
                flash(f"Erro ao lançar nota: {e}")

    # Lista todas as notas lançadas (com JOIN para mostrar o nome)
    notas = db.execute(
        """
        SELECT
            notas.id AS id,
            cadastro.nome AS nome,
            notas.disciplina AS disciplina,
            notas.nota AS nota
        FROM notas
        JOIN cadastro ON notas.id_estudante = cadastro.id
        ORDER BY cadastro.nome, notas.disciplina;
        """
    ).fetchall()

    return render_template("notas.html", estudantes=estudantes, notas=notas)

if __name__ == "__main__":
    app.run(debug=True)
