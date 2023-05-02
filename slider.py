from flask import Flask
from flask import url_for, request
from flask import render_template
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, IntegerField
from wtforms.validators import DataRequired
from flask import redirect
from wtforms.fields.html5 import EmailField
from flask_sqlalchemy import SQLAlchemy
from data.__all_models import User, Classroom, Link, Marks, GroupOfMarks, Payload


app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
@app.route('/')
@app.route('/index')
def index():
    param = {}
    param['username'] = "Пользователь"
    param['title'] = 'Домашняя страница'
    return render_template("index.html", **param)

@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)

class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect("/marks")
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/marks")
        form.email.errors.append('Неверный логин или пароль')
        return render_template('login.html', form=form)
    return render_template('login.html', title='Авторизация', form=form)

@app.route('/logout')
@login_required
def logout():
    if not current_user.is_authenticated:
        return redirect("/index")
    logout_user()
    return redirect("/")

def main():
    app.run()

from data import db_session
db_session.global_init("db/blogs.sqlite")


class RegisterForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль', validators=[DataRequired()])
    name = StringField('Имя и Фамилия', validators=[DataRequired()])
    submit = SubmitField('Войти')
    is_teacher = BooleanField('Я - учитель')


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            form.password_again.errors.append("Пароли не совпадают")
            return render_template('register.html', title='Регистрация', form=form)
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            form.email.errors.append("Такой пользователь уже есть")
            return render_template('register.html', title='Регистрация', form=form)
        user = User(
            name=form.name.data,
            email=form.email.data,
            is_teacher=form.is_teacher.data
        )
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)

@app.route('/messages')
def messages():
    return "Здесь пока ничего нет..."

@app.route('/profile')
def profile():
    if not current_user.is_authenticated:
        return redirect("/index")
    a = []
    for clas in current_user.classrooms:
        a.append(clas.code + ' - ' + clas.name)
    return render_template('profile.html', title="Профиль", a=a)

@app.route('/marks/<classcode>')
def marks_teacher(classcode):
    if not current_user.is_authenticated:
        return redirect("/index")
    if not current_user.is_teacher:
        return redirect('/marks')
    mx = 0
    session = db_session.create_session()
    classroom = session.query(Classroom).filter(Classroom.code == classcode).first()
    for i in classroom.group_of_marks:
        print(i.name)
        for j in i.marks:
            print(j.mark, j.comment)
        mx = max(mx, len(i.marks))
    return render_template('marks_for_teacher.html', mx=mx, classcode=classcode, title='Табель успеваемости', classroom=classroom)

@app.route('/marks')
def marks():
    if not current_user.is_authenticated:
        return redirect("/index")
    if current_user.is_teacher:
        for i in current_user.classrooms:
            return redirect("/marks/" + i.code)
    mx = 0
    for i in current_user.group_of_marks:
        mx = max(mx, len(i.marks))
    return render_template('marks.html', mx=mx, title='Табель успеваемости')


class ClassroomAddForm(FlaskForm):
    code = StringField('Код вашего класса', validators=[DataRequired()])
    submit = SubmitField('Добавить')


@app.route('/add_classroom', methods=['POST', 'GET'])
def add_classroom():
    if not current_user.is_authenticated:
        return redirect("/index")
    form = ClassroomAddForm()
    if current_user.is_teacher:
        return redirect('/create_classroom')
    if form.validate_on_submit():
        session = db_session.create_session()
        flag2 = False
        for i in current_user.classrooms:
            print(i.code)
            if i.code == form.code.data:
                flag2 = True
        flag = session.query(Classroom).filter(Classroom.code == form.code.data).first()
        print("len(form.code.data) != 5", len(form.code.data) != 5)
        print("all([i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' for i in form.code.data])", all([i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' for i in form.code.data]))
        print("flag", flag == None)
        print("flag2", flag2)
        if len(form.code.data) != 5 or not all([i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' for i in form.code.data]) or (flag == None) or flag2:
            form.code.errors.append("Код класса введён неверно")
            return render_template('add_classroom.html', form=form, title='Добавить класс')
        user = session.query(User).filter(User.id == current_user.id).first()
        classroom = session.query(Classroom).filter(Classroom.code == form.code.data).first()
        user.classrooms.append(classroom)
        marks = GroupOfMarks(name=current_user.name)
        user.group_of_marks.append(marks)
        classroom.group_of_marks.append(marks)
        session.add(marks)
        session.commit()
        return render_template('your_code.html', title="Класс добавлен", insert_text="Класс был успешно добавлен")
    return render_template('add_classroom.html', form=form, title='Добавить класс')


class AddMarkForm(FlaskForm):
    email = EmailField('Email ученика', validators=[DataRequired()])
    comment = StringField('Комментарий к оценке', validators=[DataRequired()])
    mark = IntegerField('Оценка (2, 3, 4, 5)', validators=[DataRequired()])
    submit = SubmitField('Выставить')

@app.route('/add_mark/<code>', methods=['GET', 'POST'])
def add_mark(code):
    if not current_user.is_authenticated:
        return redirect("/index")
    form = AddMarkForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        classroom = session.query(Classroom).filter(Classroom.code == code).first()
        flag = False
        for user in classroom.users:
            if user.email == form.email.data:
                pending_user = user
                flag = True
        if not flag:
            form.email.errors.append("Такого ученика нет в вашем классе")
            return render_template('add_mark.html', form=form, title='Выставление оценок')
        if form.mark.data not in [2, 3, 4, 5]:
            form.mark.errors.append("Оценка введена неверно")
            return render_template('add_mark.html', form=form, title='Выставление оценок')
        group = session.query(GroupOfMarks).filter(GroupOfMarks.user_id == pending_user.id, GroupOfMarks.classroom_id == classroom.id).first()
        mark = Marks(comment=form.comment.data, mark=form.mark.data)
        group.marks.append(mark)
        group.total = group.total + form.mark.data
        session.add(mark)
        session.commit()
        return render_template('mark_was_added.html', title='Успех!', code=code)
    return render_template('add_mark.html', form=form, title='Выставление оценок')


class ClassroomCreateForm(FlaskForm):
    name = StringField('Название вашего класса', validators=[DataRequired()])
    submit = SubmitField('Создать')


@app.route('/your_code/<code>')
def show_code(code):
    return render_template('your_code.html', title='Ваш код', insert_text=f"Ваш код от нового класса: {code}. Отправьте его своим ученикам")


@app.route('/create_classroom', methods=['POST', 'GET'])
def create_classroom():
    if not current_user.is_authenticated:
        return redirect("/index")
    form = ClassroomCreateForm()
    if not current_user.is_teacher:
        return redirect('/add_classroom')
    if form.validate_on_submit():
        ans = ''
        global step, p, MOD
        current_hash = get_hash()
        d = current_hash
        current_hash += step
        current_hash %= MOD
        rewrite_hash(current_hash)
        while d != 0:
            ans += sl[d % p]
            d //= p
        ans += 'A' * (5 - len(ans))
        session = db_session.create_session()
        classroom = Classroom(name=form.name.data, code=ans)
        user = session.query(User).filter(User.id == current_user.id).first()
        user.classrooms.append(classroom)
        session.add(classroom)
        session.commit()
        return redirect('/your_code/' + ans)
    return render_template('create_classroom.html', title='Создать класс', form=form)


class ChangePassword(FlaskForm):
    old_password = EmailField('Старый пароль', validators=[DataRequired()])
    new_password = PasswordField('Новый пароль', validators=[DataRequired()])
    new_password_again = PasswordField('Повторите новый пароль', validators=[DataRequired()])
    submit = SubmitField('Сменить')


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not current_user.is_authenticated:
        return redirect("/index")
    form = ChangePassword()
    if form.validate_on_submit():
        if form.new_password.data != form.new_password_again.data:
            form.new_password_again.errors.append("Новые пароли не совпадают")
            return render_template('change_password.html', title='Смена пароля', form=form)
        session = db_session.create_session()
        if not(current_user.check_password(form.old_password.data)):
            form.new_password_again.errors.append("Старый пароль неверен")
            return render_template('change_password.html', title='Смена пароля', form=form)
        user = session.query(User).filter(User.id == current_user.id).first()
        user.set_password(form.new_password.data)
        session.commit()
        return redirect('/profile')

    return render_template('change_password.html', title='Смена пароля', form=form)


def get_hash():
    session = db_session.create_session()
    payload = session.query(Payload).filter(True).first()
    return payload.cur_hash


def rewrite_hash(cur_hash):
    session = db_session.create_session()
    payload = session.query(Payload).first()
    payload.cur_hash = cur_hash
    session.commit()

if __name__ == '__main__':
    p = 26
    MOD = p ** 5
    step = 288453275

    s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    sl = {}
    for i in range(26):
        sl[i] = s[i]
    app.run()
