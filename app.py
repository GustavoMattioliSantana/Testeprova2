import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, g
)
from functools import wraps

app = Flask(__name__)

# Chave de sessão (para login simples)
app.config["SECRET_KEY"] = "chave-secreta-super-simples"
app.config["DEBUG"] = True
# Caminho do banco SQLite
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["DATABASE"] = os.path.join(BASE_DIR, "escola.db")

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
        CREATE TABLE IF NOT EXISTS cadastro ( id INTEGER PRIMARY KEY
        AUTOINCREMENT, nome TEXT NOT NULL, matricula TEXT NOT NULL UNIQUE, email
        TEXT UNIQUE );
        """
    )
    # Adicionar a coluna disciplina se ela não existir
    try:
        db.execute("ALTER TABLE usuarios ADD COLUMN disciplina TEXT;")
        db.commit()
    except sqlite3.OperationalError:
        # A coluna já existe
        pass

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            disciplina TEXT
        );
        """
    )

    # Criar um usuário admin padrão se não existir nenhum usuário
    if db.execute("SELECT COUNT(*) FROM usuarios").fetchone()[0] == 0:
        senha_admin = "admin123"  # Defina uma senha padrão segura
        senha_hash = generate_password_hash(senha_admin)
        db.execute(
            "INSERT INTO usuarios (nome, username, password_hash, role) VALUES (?, ?, ?, ?)",
            (
                "Administrador Padrão",
                "admin",
                senha_hash,
                "admin",
            ),
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

        db = get_db()
        usuario = db.execute(
            "SELECT * FROM usuarios WHERE username = ?", (username,)
        ).fetchone()

        if usuario and check_password_hash(usuario["password_hash"], password):
            session["usuario_id"] = usuario["id"]
            session["usuario"] = usuario["nome"]
            session["role"] = usuario["role"]
            if usuario["role"] == "professor":
                session["disciplina"] = usuario["disciplina"]
            flash("Login realizado com sucesso!", "success")
            if usuario["role"] == "admin":
                return redirect(url_for("admin"))
            elif usuario["role"] == "professor":
                return redirect(url_for("notas"))
            else: #aluno
                return redirect(url_for("notas"))
        else:
            flash("Usuário ou senha inválidos.", "danger")

    return render_template("index.html")

@app.route("/admin", methods=["GET", "POST"])
@login_required
def admin():
    if session.get("role") != "admin":
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("index"))

    db = get_db()

    if request.method == "POST":
        nome = request.form.get("nome")
        username = request.form.get("username")
        password = request.form.get("password")
        role = request.form.get("role")
        disciplina = request.form.get("disciplina") if role == "professor" else None

        if not nome or not username or not password or not role:
            flash("Todos os campos são obrigatórios para criar um usuário.", "warning")
        else:
            try:
                password_hash = generate_password_hash(password)
                db.execute(
                    "INSERT INTO usuarios (nome, username, password_hash, role, disciplina) VALUES (?, ?, ?, ?, ?)",
                    (nome, username, password_hash, role, disciplina),
                )
                db.commit()
                flash(f"Usuário '{username}' criado com sucesso como '{role}'.", "success")
            except sqlite3.IntegrityError:
                flash(f"O nome de usuário '{username}' já existe.", "danger")

        return redirect(url_for("admin"))

    usuarios = db.execute("SELECT id, nome, username, role, disciplina FROM usuarios").fetchall()
    return render_template("admin.html", usuarios=usuarios)

@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("index"))
    response.set_cookie("session", "", expires=0)
    flash("Você saiu do sistema.", "info")
    return response


@app.route("/estudantes", methods=["GET", "POST"])
@login_required
def estudantes():
    if session.get("role") != "admin":
        flash("Acesso não autorizado.", "danger")
        return redirect(url_for("index"))
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
                flash(f"Erro ao cadastrar estudante (dados duplicados?): {e}")
            except Exception as e:
                flash(f"Erro ao cadastrar estudante: {e}")

    estudantes = db.execute("SELECT id, nome, matricula, email FROM cadastro").fetchall()
    return render_template("estudantes.html", estudantes=estudantes)


@app.route("/notas", methods=["GET", "POST"])
@login_required
def notas():
    db = get_db()
    role = session.get("role")
    
    estudantes = db.execute(
        "SELECT id, nome, matricula FROM cadastro"
    ).fetchall()

    if request.method == "POST":
        if role == "professor":
            id_estudante = request.form.get("id_estudante")
            disciplina = session.get("disciplina")
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
        else:
            flash("Apenas professores podem lançar notas.", "danger")

    # Filtro de notas
    if role == "professor":
        disciplina_professor = session.get("disciplina")
        notas_query = """
            SELECT n.id, c.nome, n.disciplina, n.nota
            FROM notas n JOIN cadastro c ON n.id_estudante = c.id
            WHERE n.disciplina = ?
            ORDER BY c.nome, n.disciplina;
        """
        notas = db.execute(notas_query, (disciplina_professor,)).fetchall()
    elif role == "aluno":
        usuario_id = session.get("usuario_id")
        # Encontrar o id do estudante no cadastro com base no nome de usuário
        aluno_info = db.execute("SELECT id FROM cadastro WHERE matricula = (SELECT username FROM usuarios WHERE id = ?)", (usuario_id,)).fetchone()
        if aluno_info:
            id_estudante = aluno_info['id']
            notas_query = """
                SELECT n.id, c.nome, n.disciplina, n.nota
                FROM notas n JOIN cadastro c ON n.id_estudante = c.id
                WHERE n.id_estudante = ?
                ORDER BY n.disciplina;
            """
            notas = db.execute(notas_query, (id_estudante,)).fetchall()
        else:
            notas = []
            flash("Nenhum cadastro de estudante encontrado para este usuário.", "warning")
    else: # admin
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

    return render_template("notas.html", estudantes=estudantes, notas=notas, role=role)


if __name__ == "__main__":
    app.run(debug=True)