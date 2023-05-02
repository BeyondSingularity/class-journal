import datetime
import sqlalchemy
from sqlalchemy import create_engine, ForeignKey, Column, Integer, String, DateTime, Boolean

import datetime
from .db_session import SqlAlchemyBase
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from sqlalchemy import orm

class User(SqlAlchemyBase, UserMixin):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, nullable=True)
    email = Column(String, index=True, unique=True, nullable=True)
    is_teacher = Column(Boolean, default=False)
    hashed_password = Column(String, nullable=True)
    created_date = Column(DateTime, default=datetime.datetime.now)

    classrooms = orm.relationship('Classroom', secondary='link', lazy='subquery')
    group_of_marks = orm.relation('GroupOfMarks', back_populates='user')

    def set_password(self, password):
        self.hashed_password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.hashed_password, password)


class Classroom(SqlAlchemyBase):
    __tablename__ = 'classroom'

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String, nullable=True)
    name = Column(String, nullable=True)
    created_date = Column(DateTime, default=datetime.datetime.now)
    users = orm.relationship('User', secondary='link')
    group_of_marks = orm.relationship('GroupOfMarks', back_populates='classroom', lazy='subquery')


class Link(SqlAlchemyBase):
    __tablename__ = 'link'

    classroom_id = Column(Integer, ForeignKey('classroom.id'), primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), primary_key=True)


class GroupOfMarks(SqlAlchemyBase):
    __tablename__ = 'group_of_marks'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('user.id'))
    classroom_id = Column(Integer, ForeignKey('classroom.id'))
    user = orm.relation('User')
    total = Column(Integer, nullable=True, default=0)
    name = Column(String, nullable=True)
    classroom = orm.relation('Classroom')
    marks = orm.relation('Marks', back_populates='group_of_marks')


class Marks(SqlAlchemyBase):
    __tablename__ = 'marks'

    group_of_marks_id = Column(Integer, ForeignKey('group_of_marks.id'))
    id = Column(Integer, primary_key=True, autoincrement=True)
    mark = Column(Integer, nullable=True)
    group_of_marks = orm.relation('GroupOfMarks')
    comment = Column(String, default='', nullable=True)
    date = Column(String, default='.'.join([str(0) * (2 - len(str(i))) + str(i) for i in datetime.datetime.now().timetuple()[1:3][::-1]]))


class Payload(SqlAlchemyBase):
    __tablename__ = "payload"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cur_hash = Column(Integer, nullable=True, default=92734)