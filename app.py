from sre_parse import State
from tkinter.ttk import Label
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user, login_user, logout_user, login_required, UserMixin
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, DateField,DateTimeField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort
from datetime import datetime
from sqlalchemy import exc
import logging
import calendar
from calendar import monthrange

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False)
    name= db.Column(db.String(20), nullable=False)
    surname= db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    privilege = db.Column(db.String(60), nullable=False)
    supervisor = db.Column(db.String(60), nullable=False, default='.')
    status = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    helpdesks = db.relationship('Helpdesk', backref='author', lazy=True)
    user_infos = db.relationship('User_info', backref='author', lazy=True)
    orders = db.relationship('Order', backref='author', lazy=True)
    
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class User_info(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    surname = db.Column(db.String(120))
    department = db.Column(db.String(100))
    street = db.Column(db.String(120))
    house_number = db.Column(db.String(120))
    post_code = db.Column(db.String(120))
    city = db.Column(db.String(120))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    def __repr__(self):
        return f"User_info('{self.name}', '{self.surname}', '{self.id}', '{self.user_id}' )"

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    typ = db.Column(db.String(20), nullable=False)
    worker_name = db.Column(db.String(20), nullable=False)
    worker_surname = db.Column(db.String(120), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    supervisor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    supervisor = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    date_start = db.Column(db.DateTime, nullable=False)
    date_end = db.Column(db.DateTime, nullable=False)
    login = db.Column(db.String(100))
    login_status = db.Column(db.String(100), default='In progress')
    email = db.Column(db.String(100))
    email_status = db.Column(db.String(100), default='In progress')
    status = db.Column(db.String(100), default='In progress')
    privilege = db.Column(db.String(100))
    user_id = db.Column(db.String(100))
    status_cancel = db.Column(db.String(100), default='-')
    def __repr__(self):
        return f"Order('{self.worker_name}', '{self.worker_surname}', '{self.id}', '{self.supervisor_id}', '{self.login}', '{self.date_start}' )"

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(100), default='Active')

    def __repr__(self):
        return f"Item('{self.name}','{self.status}')"

class Order_item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_order =  db.Column(db.String(100), default='')
    id_item = db.Column(db.String(100), default='')
    name =  db.Column(db.String(100), default='')
    value = db.Column(db.String(100), default='')
    status = db.Column(db.String(100), default='In progress')
    
    def __repr__(self):
        return f"Item('{self.name}','{self.status}')"

class Absence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(100), default='Active')

    def __repr__(self):
        return f"Absence('{self.name}','{self.status}')"

class User_Absence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.String(100), nullable=False)
    end_date = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(100), default='')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name_and_surname = db.Column(db.String(100), nullable=False)
    supervisor = db.Column(db.String(100), default='')

    def __repr__(self):
        return f"User_Absence('{self.id}','{self.name}','{self.user_id}')"

class User_Absence_Limit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    id_absence = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.String(100), nullable=False)
    end_date = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.String(100), default='')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"User_Absence_Limit('{self.id}','{self.name}','{self.user_id}')"

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}')"

class Ticket_reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user = db.Column(db.Text, nullable=False)
    
    def __repr__(self):
            return f"Ticket('{self.id}','{self.ticket_id}','{self.content}', '{self.date_posted}')"

class Helpdesk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(100))
    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(100), default='In progress')

    def __repr__(self):
        return f"Helpdesk('{self.title}', '{self.date_posted}')"


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    surname = StringField('Surname',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    privilege = SelectField('Rola',  choices=['User','Admin','Manager'])
    submit = SubmitField('Sign Up')

    #def validate_username(self, username):
    #    user = User.query.filter_by(username=username.data).first()
    #    if user:
    #        raise ValidationError('That username is Yesen. Please choose a different one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is Yesen. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is Yesen. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is Yesen. Please choose a different one.')


class OrderForm1(FlaskForm):
    worker_name = StringField('Name', validators=[DataRequired()])
    worker_surname = StringField('Surname', validators=[DataRequired()])
    department = SelectField('Department', validators=[DataRequired()], choices=['','Hr','IT'])
    date_start = DateTimeField('Start Date', format='%d.%m.%Y')
    date_end = DateTimeField('End Date', format='%d.%m.%Y')
    privilege = SelectField('Privilege', validators=[DataRequired()], choices=['User','Manager'])
    
    submit = SubmitField('Post')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

class OrderFormStatus1(FlaskForm):
    worker_name = StringField('Name', validators=[DataRequired()])
    worker_surname = StringField('Surname', validators=[DataRequired()])
    department = SelectField('Department', validators=[DataRequired()], choices=['','Hr','IT'])
    date_start = DateTimeField('Start Date', format='%d.%m.%Y')
    date_end = DateTimeField('End Date', format='%d.%m.%Y')
    login = StringField('Login', validators=[DataRequired()])
    login_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    email = StringField('E-mail', validators=[DataRequired()])
    email_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    privilege = SelectField('Privilege', validators=[DataRequired()], choices=['User','Admin'])

    submit = SubmitField('Post')
    

class EditOrderFormStatus(FlaskForm):
    worker_name = StringField('Name', validators=[DataRequired()])
    worker_surname = StringField('Surname', validators=[DataRequired()])
    department = SelectField('Department', validators=[DataRequired()], choices=['','Hr','IT'])
    date_start = DateTimeField('Start Date', format='%d.%m.%Y')
    date_end = DateTimeField('End Date', format='%d.%m.%Y')
    login = StringField('Login', validators=[DataRequired()])
    login_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    laptop = SelectField('Laptop', validators=[DataRequired()], choices=['-','Yes','No'])
    laptop_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    laptop_remove = BooleanField('Remove?')
    email = StringField('E-mail', validators=[DataRequired()])
    email_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    email_remove = BooleanField('Remove?')
    access1 = SelectField('System 1', validators=[DataRequired()], choices=['-','Yes','No'])
    access1_type = SelectField('Role to System 1', validators=[DataRequired()], choices=['-','User','Admin','Operator'])
    access1_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access1_remove = BooleanField('Remove?')
    access1_type_remove = BooleanField('Remove?')
    access1_type_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access2 = SelectField('System 2', validators=[DataRequired()], choices=['-','Yes','No'])
    access2_type = SelectField('Role to System 2', validators=[DataRequired()], choices=['-','User','Admin','Operator'])
    access2_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access2_type_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access2_remove = BooleanField('Remove?')
    access2_type_remove = BooleanField('Remove?')
    access3 = SelectField('System 3', validators=[DataRequired()], choices=['-','Yes','No'])
    access3_type = SelectField('Role to System 2', validators=[DataRequired()], choices=['-','User','Admin','Operator'])
    access3_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access3_type_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access3_remove = BooleanField('Remove?')
    access3_type_remove = BooleanField('Remove?')
    access4 = SelectField('System 4', validators=[DataRequired()], choices=['-','Yes','No'])
    access4_type = SelectField('Role to System 4', validators=[DataRequired()], choices=['-','User','Admin','Operator'])
    access4_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access4_type_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    access4_remove = BooleanField('Remove?')
    access4_type_remove = BooleanField('Remove?')
    privilege = SelectField('Privilege', validators=[DataRequired()], choices=['User','Admin'])

    submit = SubmitField('Post')

class EditOrderFormStatus1(FlaskForm):
    worker_name = StringField('Name', validators=[DataRequired()])
    worker_surname = StringField('Surname', validators=[DataRequired()])
    department = SelectField('Department', validators=[DataRequired()], choices=['','Hr','IT'])
    date_start = DateTimeField('Start Date', format='%d.%m.%Y')
    date_end = DateTimeField('End Date', format='%d.%m.%Y')
    login = StringField('Login', validators=[DataRequired()])
    login_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    email = StringField('E-mail', validators=[DataRequired()])
    email_status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done','Canceled'])
    email_remove = BooleanField('Remove?')
    privilege = SelectField('Privilege', validators=[DataRequired()], choices=['User','Admin'])

    submit = SubmitField('Post')

class AddOrderItemForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    submit = SubmitField('Post')



class TicketHelpdeskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    department = SelectField('Department', validators=[DataRequired()], choices=['HR','Helpdesk'])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')

class TicketHelpdeskReplyForm(FlaskForm):
    content = TextAreaField('Reply content', validators=[DataRequired()])
    status = SelectField('Status', validators=[DataRequired()], choices=['In progress','Done'])
    submit = SubmitField('Send')

class User_infoForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    surname = StringField('Surname', validators=[DataRequired()])
    department = SelectField('Department', validators=[DataRequired()], choices=['','HR','IT'])
    street = StringField('Street', validators=[DataRequired()])
    house_number = StringField('House number', validators=[DataRequired()])
    post_code = StringField('Post code', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    submit = SubmitField('Send')


@app.route("/home")
def home():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    users = User.query.filter_by(supervisor=current_user.username + " " + current_user.surname).order_by(User.surname.desc()).paginate(page=page, per_page=10) 
    users_absences = User_Absence.query.filter_by(status='to accept').all()
    if current_user.privilege =='Manager':
        orders = Order.query.filter_by(supervisor_id=current_user.id,status='In progress').order_by(Order.date_posted.desc()).paginate(page=page, per_page=10)
        return render_template('home.html',users=users,users_absences=users_absences, posts=posts, orders=orders)

    elif current_user.privilege=='Admin':
        orders = Order.query.filter_by(status='In progress').order_by(Order.date_posted.desc()).paginate(page=page, per_page=10)      
        return render_template('home.html',users=users,users_absences=users_absences, posts=posts, orders=orders)

    return render_template('home.html',users=users,users_absences=users_absences, posts=posts)
    
@app.route("/about")
def about():
    return render_template('about.html', title='About')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated and current_user.privilege=='User':
        return redirect(url_for('about'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, surname=form.surname.data, name=form.username.data, email=form.email.data, password=hashed_password, privilege=form.privilege.data,status='Active')
        db.session.add(user)
        db.session.commit()
        if current_user.is_authenticated:
            flash('Account has been created!', 'success')
            return redirect(url_for('mgmt_users'))
        else:
            flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
@app.route("/", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('about'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, status='Active').first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    #elif request.method == 'GET':
        #form.username.data = current_user.username
        #form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)




@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        form = PostForm()
        if form.validate_on_submit():
            post = Post(title=form.title.data, content=form.content.data, author=current_user)
            db.session.add(post)
            db.session.commit()
            flash('Your post has been created!', 'success')
            return redirect(url_for('about'))
        return render_template('create_post.html', title='New Post',
                            form=form, legend='New Post')

@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Update Post',
                           form=form, legend='Update Post')

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('posts'))

@app.route("/user/<string:username>")
@login_required
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)

@app.route("/posts")
@login_required
def posts():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('posts.html', posts=posts)


@app.route("/hd_ticket/new", methods=['GET', 'POST'])
@login_required
def new_helpdesk_ticket():
    form = TicketHelpdeskForm() 
    if form.validate_on_submit():
        helpdesk = Helpdesk(title=form.title.data, department=form.department.data, content=form.content.data, author=current_user)
        db.session.add(helpdesk)
        db.session.commit()
        flash('Your helpdesk request has been created!', 'success')
        return render_template('helpdesk_ticket.html', title=helpdesk.title, ticket=helpdesk)
    return render_template('create_helpdesk_ticket.html', title='New Helpdesk Ticket', form=form, legend='New Helpdesk Ticket')

@app.route("/helpdesk_ticket/<int:ticket_id>", methods=['GET', 'POST'])
def helpdesk_ticket(ticket_id):
    ticket = Helpdesk.query.get_or_404(ticket_id)
    replys = Ticket_reply.query.filter_by(ticket_id=ticket.id).order_by(Ticket_reply.date_posted.asc())
    form = TicketHelpdeskReplyForm()
    
    if form.validate_on_submit():
        ticket_reply = Ticket_reply(ticket_id=ticket.id, content=form.content.data, user = current_user.username) 
        db.session.add(ticket_reply)
        if form.status.data == 'Done':
            ticket.status = 'Done'
        db.session.commit()
        flash('Your reply has been send!', 'success')
    form.content.data = ""
    return render_template('Reply_helpdesk_ticket.html',replys=replys, ticket=ticket, title='Reply ticket', form=form, legend='Reply ticket')


@app.route("/helpdesk_ticket/<int:ticket_id>/reply", methods=['GET', 'POST'])
@login_required
def reply_helpdesk_ticket(ticket_id):
    ticket = Helpdesk.query.get_or_404(ticket_id)
    replys = Ticket_reply.query.filter_by(ticket_id=ticket.id).order_by(Ticket_reply.date_posted.asc())
    form = TicketHelpdeskReplyForm()
    
    if form.validate_on_submit():
        ticket_reply = Ticket_reply(ticket_id=ticket.id, content=form.content.data, user = current_user.username) 
        db.session.add(ticket_reply)
        if form.status.data == 'Done':
            ticket.status = 'Done'
        db.session.commit()
        flash('Your reply has been send!', 'success')
    form.content.data = ""
    return render_template('Reply_helpdesk_ticket.html',replys=replys, ticket=ticket, title='Reply ticket', form=form, legend='Reply ticket')


@app.route("/user_helpdesk_tickets/<string:username>")
@login_required
def user_helpdesk_tickets(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    tickets = Helpdesk.query.filter_by(author=user)\
        .paginate(page=page, per_page=5)
    return render_template('user_helpdesk_tickets.html', tickets=tickets, user=user)


@app.route("/helpdesk_tickets")
@login_required
def helpdesk_tickets():
    page = request.args.get('page', 1, type=int)
    tickets = Helpdesk.query.order_by(Helpdesk.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('helpdesk_tickets.html', tickets=tickets)

@app.route("/mgmt")
@login_required
def mgmt():
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        return render_template('mgmt.html')


@app.route("/mgmt/users/")
@login_required
def mgmt_users():
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        page = request.args.get('page', 1, type=int)
        users = User.query.filter_by(status='Active').order_by(User.username.desc()).paginate(page=page, per_page=10) 
        return render_template('mgmt_users.html', users=users)
        

@app.route("/mgmt/users_inactive")
@login_required
def mgmt_users_inactiv():
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        page = request.args.get('page', 1, type=int)
        users = User.query.filter_by(status='Inactiv').order_by(User.status.desc()).paginate(page=page, per_page=10) 
        return render_template('mgmt_users_inactiv.html', users=users)


@app.route('/delete_user/<int:user_id>', methods=['GET','POST'])
@login_required
def delete_user(user_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        user = User.query.filter_by(id=user_id).first()
        user.status = 'Inactiv'
        
        db.session.commit()
        flash('User has been deleted!', 'success')
        return redirect(url_for('mgmt_users'))

@app.route('/restore_user/<int:user_id>', methods=['GET','POST'])
@login_required
def restore_user(user_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        user = User.query.get_or_404(user_id)
        user.status = 'Active'
        
        db.session.commit()
        flash('User has been restored!', 'success')
        return redirect(url_for('mgmt_users'))
        
@app.route('/mgmt_user_info_view/<int:user_id>', methods=['POST','GET'])
@login_required
def mgmt_user_info_view(user_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        user = User.query.filter_by(id=user_id).first_or_404()
        try:
            user_info = User_info.query.filter_by(user_id=user_id).first_or_404()
            return render_template('mgmt_user_info_view.html', user_id=user_id, user=user, user_info=user_info)
        except:
            #flash('the user did not complete the data ','danger')
            return render_template('mgmt_user_info_view.html', user=user)


@app.route('/mgmt_edit_user/<int:user_id>', methods=['GET','POST'])
@login_required
def mgmt_edit_user(user_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        form = User_infoForm()
        form1 = User_infoForm()   
        user = User.query.filter_by(id=user_id).first_or_404()
        try:
            user_info_view = User_info.query.filter_by(id=user_id).first_or_404()
            form.name.data=user_info_view.name
            form.surname.data=user_info_view.surname
            form.department.data=user_info_view.department
            form.street.data=user_info_view.street
            form.house_number.data=user_info_view.house_number
            form.post_code.data=user_info_view.post_code
            form.city.data=user_info_view.city
        except:
            user_info_view = 0

        if request.method=='POST':    
            if form.validate_on_submit():      
                try:
                    user_info = User_info(name=form.name.data, surname=form.surname.data,\
                department=form.department.data, street=form.street.data, house_number=form.house_number.data, \
                    post_code=form.post_code.data, city=form.city.data, user_id=user_id) 
                    db.session.add(user_info)
                    db.session.commit()
                    flash('User info has been created!', 'success')
                    return redirect(url_for('about'))

                except exc.SQLAlchemyError :
                    db.session.rollback()
                    #flash('User info cant be created!', 'danger')                 
                    user_info = User_info.query.filter_by(id=user_id).first()
                    user_info.name=form1.name.data
                    user_info.surname=form1.surname.data
                    user_info.department=form1.department.data
                    user_info.street=form1.street.data
                    user_info.house_number=form1.house_number.data
                    user_info.post_code=form1.post_code.data
                    user_info.city=form1.city.data

                    db.session.commit()
                    flash('User info has been updated!','success')
                    return redirect(url_for('about'))
        return render_template('mgmt_user_create_info.html', form=form, user_id=user_id,user=user, user_info_view=user_info_view)
    
        
@app.route('/edit_user/<int:user_id>', methods=['GET','POST'])
@login_required
def edit_user(user_id):
    user_id = current_user.id
    form = User_infoForm()
    form1 = User_infoForm()   
    user = User.query.filter_by(id=user_id).first_or_404()
    try:
        user_info_view = User_info.query.filter_by(user_id=user_id).first_or_404()
        form.name.data=user_info_view.name
        form.surname.data=user_info_view.surname
        form.department.data=user_info_view.department
        form.street.data=user_info_view.street
        form.house_number.data=user_info_view.house_number
        form.post_code.data=user_info_view.post_code
        form.city.data=user_info_view.city
    except:
        user_info_view = 0
     
    if request.method=='POST':    
        if form.validate_on_submit():      
            try:
                user_info = User_info(name=form.name.data, surname=form.surname.data,\
             department=form.department.data, street=form.street.data, house_number=form.house_number.data, \
                 post_code=form.post_code.data, city=form.city.data, user_id=user_id) 
               
                db.session.add(user_info)
                db.session.commit()
                #flash('User info has been created!', 'success')
                return redirect(url_for('about'))

            except exc.SQLAlchemyError :
                db.session.rollback()
                #flash('User info cant be created!', 'danger')                 
                user_info = User_info.query.filter_by(user_id=user_id).first()
                user_info.name=form1.name.data
                user_info.surname=form1.surname.data
                user_info.department=form1.department.data
                user_info.street=form1.street.data
                user_info.house_number=form1.house_number.data
                user_info.post_code=form1.post_code.data
                user_info.city=form1.city.data

                db.session.commit()
                flash('User info has been updated!','success')
                return redirect(url_for('about'))
    return render_template('user_create_info.html', form=form, user_id=user_id,user=user, user_info_view=user_info_view)
    

@app.route('/absences/<int:user_id>', methods=['GET','POST'])
@login_required
def absences_user(user_id):
    user_id = current_user.id
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    user = User.query.filter_by(id=user_id).first_or_404()
    user_info_view = User_info.query.filter_by(user_id=user_id).first()
    absences=Absence.query.filter_by(status='Active').order_by(Absence.id.desc())
    user_absences = User_Absence.query.filter_by(user_id=user_id).order_by(User_Absence.id.desc())
    absence_limits = User_Absence_Limit.query.filter_by(user_id=user_id).order_by(User_Absence_Limit.name.desc())

    if request.method=='POST':
        try:
            value=request.form.get("absence_item")
            start_date = datetime.strptime(request.form.get("start_date"), '%Y-%m-%d').date()
            end_date = datetime.strptime(request.form.get("end_date"), '%Y-%m-%d').date()
            amount_absence = 1+(end_date-start_date).days
            limit_amount = User_Absence_Limit.query.filter_by(user_id=user_id).filter_by(name=value).first()
            limit = int(limit_amount.amount) - int(amount_absence)
            if start_date=="" or end_date=="" or value=="":
                flash('complete all fields','danger')
            else:
                absence = User_Absence(name = value, start_date=start_date, end_date=end_date, status='to accept', user_id=current_user.id, name_and_surname = current_user.name + " " + current_user.surname, supervisor=user.supervisor)
                limit_amount.amount = limit
                db.session.add(absence)
                db.session.commit()  
                flash('Absence has been create','success')
                return render_template('absences_user.html', user_absences=user_absences,absences=absences, user_id=user_id, user=user, user_info_view=user_info_view,image_file=image_file,absence_limits=absence_limits)
        except:
            flash('You cant sent this absence','danger')
    return render_template('absences_user.html', user_absences=user_absences,absences=absences, user_id=user_id, user=user, user_info_view=user_info_view,image_file=image_file,absence_limits=absence_limits)

@app.route('/delete_absence/<int:absence_id>', methods=['GET','POST'])
@login_required
def delete_absence(absence_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        absence = Absence.query.filter_by(id=absence_id).first()
        absence.status = 'Inactiv'
        db.session.commit()
        flash('Absence has been deleted!', 'success')
        return redirect(url_for('mgmt_absence_add_item'))

@app.route('/restore_absence/<int:absence_id>', methods=['GET','POST'])
@login_required
def restore_absence(absence_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        absence = Absence.query.get_or_404(absence_id)
        absence.status = 'Active'
        db.session.commit()
        flash('Absence has been restored!', 'success')
        return redirect(url_for('mgmt_absence_add_item'))

@app.route("/mgmt_absence/add_item", methods=['GET','POST'])
def mgmt_absence_add_item():
    form = AddOrderItemForm()
    if form.validate_on_submit():
        name = form.name.data
        absence_item = Absence(name=name, status='Active')
        db.session.add(absence_item)                
        db.session.commit()
        flash('Item has been add','success')
    form.name.data=""
    absence_items=Absence.query.order_by(Absence.id.desc())
    return render_template('mgmt_absence_add_item.html', form=form, absence_items=absence_items)

@app.route("/mgmt_absence_add_limit/<int:user_id>", methods=['GET','POST'])
def mgmt_absence_add_limit(user_id):
    
    user = User.query.filter_by(id=user_id).first_or_404()
    user_info_view = User_info.query.filter_by(user_id=user_id).first()
    absences=Absence.query.filter_by(status='Active').order_by(Absence.id.desc())
    absence_limits = User_Absence_Limit.query.filter_by(user_id=user_id).order_by(User_Absence_Limit.name.desc())

    if request.method=='POST':
        name = request.form.get('absence_item')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        amount = request.form.get('amount')
        absence=Absence.query.filter_by(name=name).first()
        id_absence=absence.id
        absence_limit = User_Absence_Limit(id_absence=id_absence, name=name, start_date=start_date, end_date=end_date, amount = amount,user_id=user_id)
        db.session.add(absence_limit)                
        db.session.commit()
        flash('Limit has been add','success')
        absence_limits = User_Absence_Limit.query.filter_by(user_id=user_id).order_by(User_Absence_Limit.name.desc())
        page = request.args.get('page', 1, type=int)
        users = User.query.filter_by(supervisor=current_user.username + " " + current_user.surname).order_by(User.surname.desc()).paginate(page=page, per_page=10) 
        return render_template('mgmt_hr.html',users=users, page=page, absence_limits=absence_limits)
    return render_template('mgmt_absence_add_limit.html', user_info_view=user_info_view, user=user, absences=absences, absence_limits=absence_limits,)

@app.route("/mgmt_hr")
@login_required
def mgmt_hr():
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        #try:
            page = request.args.get('page', 1, type=int)
            users = User.query.filter_by(supervisor=current_user.username + " " + current_user.surname).order_by(User.surname.desc()).paginate(page=page, per_page=10) 
            users_absences = User_Absence.query.all()
            
            return render_template('mgmt_hr.html',users_absences=users_absences, users=users, page=page)
        #except:
            #flash('You dont have employee','danger')
            #posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
            #return render_template('home.html', posts=posts)

@app.route('/mgmt_accept_absence/<int:absence_id>', methods=['GET','POST'])
@login_required
def mgmt_accept_absence(absence_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        users_absences = User_Absence.query.filter_by(id=absence_id).first()
        users_absences.status='Accept'
        db.session.commit()
        flash('Absence has been accepted!','success')
        return redirect(url_for('mgmt_hr'))
        

@app.route('/mgmt_cancel_absence/<int:absence_id>', methods=['GET','POST'])
@login_required
def mgmt_cancel_absence(absence_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:                
            users_absences = User_Absence.query.filter_by(id=absence_id).first()
            users_absences.status='Cancel'
            db.session.commit()
            flash('Absence has been canceled!','success')
            return redirect(url_for('mgmt_hr'))

@app.route('/my_calendar/<int:user_id>', methods=['POST','GET'])
@login_required
def my_calendar(user_id):
    user_id = current_user.id
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    user = User.query.filter_by(id=user_id).first_or_404()
    user_info_view = User_info.query.filter_by(user_id=user_id).first()
    user_absences = User_Absence.query.filter_by(user_id=user_id).order_by(User_Absence.id.desc())
        
    now = datetime.now()
    year = now.year
    today = now.day
    mount = now.month
    days = int(monthrange(year,mount)[1])
    day_of_absences = []
    for user_absence in user_absences:
        mounth_of_absences = (datetime.strptime(user_absence.start_date, '%Y-%m-%d').date()).month
        if mounth_of_absences == mount:
            if (datetime.strptime(user_absence.start_date, '%Y-%m-%d').date()).day != (datetime.strptime(user_absence.end_date, '%Y-%m-%d').date()).day:
                for i in range((datetime.strptime(user_absence.start_date, '%Y-%m-%d').date()).day,(datetime.strptime(user_absence.end_date, '%Y-%m-%d').date()).day+1):
                    day_of_absences.append(i)
            else:
                day_of_absences.append((datetime.strptime(user_absence.start_date, '%Y-%m-%d').date()).day)
          
        
        
    return render_template('my_calendar.html',day_of_absences=day_of_absences,today=today,days=days,mount=mount,year=year,user_absences=user_absences,image_file=image_file,user=user,user_info_view=user_info_view)
        

@app.route("/order/my_employee")
@login_required
def my_users_orders():
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        page = request.args.get('page', 1, type=int)
        orders = Order.query.filter_by(supervisor_id=current_user.id).order_by(Order.date_posted.desc()).paginate(page=page, per_page=10)
        return render_template('my_users_orders.html', orders=orders)  

@app.route("/mgmt_orders")
@login_required
def mgmt_orders():
    return render_template('mgmt_orders.html')

@app.route("/mgmt_order/add_item", methods=['GET','POST'])
@login_required
def mgmt_order_add_item():
    
    form = AddOrderItemForm()
    if form.validate_on_submit():
        name = form.name.data
        order_item = Item(name=name, status='Active')
        db.session.add(order_item)                
        db.session.commit()
        flash('Item has been add','success')
    form.name.data=""    
    order_items=Item.query.order_by(Item.id.desc())

    return render_template('mgmt_order_add_item.html', form=form, order_items=order_items)            

@app.route("/new", methods=['GET', 'POST'])
@login_required
def new_employee():
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:
        form = OrderForm1()
        order_items=Item.query.order_by(Item.name.desc())
        if request.method=='POST':   
            if form.validate_on_submit():
                i=0
                licz = 0
                login=form.worker_name.data[0].lower()+form.worker_surname.data.lower().replace('ą','a').replace('ę','e').replace('ć','c').replace('ł','l').replace('ń','n').replace('ó','o').replace('ś','s').replace('ź','z').replace('ż','z') 
                login2 = login
                while licz == 0:
                    try:
                        login_in_db = Order.query.filter_by(login=login).first()
                        login_in_db=login_in_db.login
                        if login_in_db==login: i=i+1
                        else: licz = 1
                    except:
                        licz = 1
                    login = login2 + str(i)
                if i==0: login = login2
                else: login = login2 + str(i)
                email = login+'@gmail.com'

                order = Order(typ='New Employee', worker_name=form.worker_name.data, worker_surname=form.worker_surname.data, \
                    department=form.department.data, date_start=form.date_start.data, date_end=form.date_end.data, \
                        login=login, email=email, privilege=form.privilege.data ,supervisor=current_user.username + " " + current_user.surname,\
                            supervisor_id=current_user.id,user_id='brak')
                db.session.add(order)
                db.session.commit()
                order = Order.query.filter_by(login=login).first()
                
                for order_item in order_items:
                    value1=request.form.get("order_item_"+str(order_item.id))
                    order_itemms= Order_item(id_order=order.id, id_item=order_item.id, name = order_item.name, value = value1, status='In progress')
                    db.session.add(order_itemms)
                    db.session.commit()    
                    
                flash('Your Order has been created!', 'success')
                return redirect(url_for('orders')) 
        return render_template('create_order.html', form=form, order_items=order_items)

@app.route("/orders")
@login_required
def orders():
    page = request.args.get('page', 1, type=int)
    if current_user.privilege =='Manager':
        orders = Order.query.filter_by(supervisor_id=current_user.id).order_by(Order.date_posted.desc()).paginate(page=page, per_page=10)
    elif current_user.privilege=='Admin':
        orders = Order.query.order_by(Order.date_posted.desc()).paginate(page=page, per_page=10)
    return render_template('orders.html', orders=orders)

@app.route("/order/<int:order_id>")
def order(order_id):
    order = Order.query.get_or_404(order_id)
    order_items = Order_item.query.filter_by(id_order=order.id)
    return render_template('order.html', order=order, order_items=order_items )

@app.route("/realization_order/<int:order_id>", methods=['GET', 'POST'])
@login_required
def realization_order(order_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:        
        form = OrderFormStatus1()
        order  = Order.query.get_or_404(order_id)
        form.login.data = order.login
        form.login_status.data = order.login_status
        form.email.data = order.email
        form.email_status.data = order.email_status     
        order_items = Order_item.query.filter_by(id_order=order.id).all()
        
        if request.method=='POST':
            if request.form["btn"] == "Done all":
                order.login = form.login.data
                order.login_status = 'Done'
                order.email = form.email.data
                order.email_status = 'Done'
                if order.typ == 'New Employee' and order.login_status =='Done' and order.email_status =='Done' and order.user_id=='brak':   
                    hashed_password = bcrypt.generate_password_hash('kamil0oo').decode('utf-8')
                    user = User(username=form.login.data, name=order.worker_name, surname=order.worker_surname , email=form.email.data, password=hashed_password, privilege=order.privilege, status='Active', supervisor=order.supervisor)
                    username=form.login.data
                    db.session.add(user)                
                    db.session.commit()
                    user=User.query.filter_by(username=username).first()
                    order.user_id = user.id 
                    db.session.commit()
                    flash('Account '+order.login+' has been created!', 'success') 
                
                for order_item in order_items:
                    if order_item.value == 'Yes' and order_item.status=='Done':
                        order_item.status='Done'
                    elif order_item.value == 'Yes' and order_item.status=='Canceled':
                        order_item.status='Canceled'
                    elif (order_item.value == 'Yes' or order_item.value == 'to remove') and order_item.status=='In progress':
                        order_item.status = 'Done'
                    elif order_item.value == '-' and order_item.status=='In progress':
                        order_item.status = '-'
                    elif order_item.value == 'Yes' and order_item.status=='In progress':
                        order_item.status = 'Done'    
                    db.session.commit() 
                    
                order.status='Done'
                db.session.commit()     
                flash('Order info has been updated!','success')
            else:    
                form = OrderFormStatus1()
                order.login = form.login.data
                if order.login_status=='Done':
                    order.login_status='Done'
                elif order.login_status=='Canceled':
                    order.login_status='Canceled'
                else:
                    order.login_status = form.login_status.data                
                order.email = form.email.data
                if order.email_status=='Done':
                    order.email_status='Done'
                elif order.email_status=='Canceled':
                    order.email_status='Canceled'
                else:
                    order.email_status = form.email_status.data 

                db.session.commit()
                flash('Order info has been updated!','success')
                    
                if order.typ == 'New Employee' and order.login_status =='Done' and order.email_status =='Done' and order.user_id=='brak':   
                    hashed_password = bcrypt.generate_password_hash('kamil0oo').decode('utf-8')
                    user = User(username=form.login.data,surname = order.surname, email=form.email.data, password=hashed_password, privilege=order.privilege, status='Active', supervisor=order.supervisor)
                    username=form.login.data
                    db.session.add(user)                
                    db.session.commit()
                    user=User.query.filter_by(username=username).first()
                    order.user_id = user.id 
                    db.session.commit()
                    flash('Account '+order.login+' has been created!', 'success')    
                    
                for order_item in order_items:
                    if order_item.status=='Done':
                        order_item.status='Done'
                    elif order_item.status=='Canceled':
                        order_item.status='Canceled'
                    else:
                        value1=request.form.get("order_item_"+str(order_item.id))
                        order_item.status = value1
                        db.session.commit()    
            licz = 0
            order_items = Order_item.query.filter_by(id_order=order.id).all()
            for order_item in order_items:
                if order_item.status == 'In progress':
                    order.status = 'In progress'
                    licz = licz+1
                if licz == 0: 
                    order.status = 'Done'
                else:
                    order.status='In progress'
                db.session.commit() 

        return render_template('realization_order.html', form=form, order=order, order_items=order_items)



@app.route("/edit_access_employee/<int:user_id>", methods=['GET', 'POST'])
@login_required
def edit_access_employee(user_id):
    if current_user.privilege=='User':
        return redirect(url_for('about'))
    else:        
        form = EditOrderFormStatus1()
        order  = Order.query.filter_by(user_id=user_id, status_cancel='-').order_by(Order.id.desc()).first()
        order_items = Order_item.query.filter_by(id_order=order.id).all()
        dostepy = []
        for order_item in order_items:
            dostepy.append(order_item.name)
        items=Item.query.order_by(Item.id.desc())
        pozycje = []
        for item in items:
            pozycje.append(item.name)
        differences=[]
        for list in pozycje:
            if list not in dostepy:
                differences.append(list)
                

        form.date_start.data = order.date_start
        form.date_end.data = order.date_end
        
        for order_item in order_items:
            if order_item.status == 'Canceled':
                order_item.value='-'
                order_item.status == 'Canceled'
            
        if request.method=='POST':
            try:
                form = EditOrderFormStatus1()
                #order  = Order.query.filter_by(user_id=user_id).order_by(Order.id.desc()).first()
                order.date_start = form.date_start.data
                order.date_end = form.date_end.data
    
                order1 = Order(typ='Edit access', worker_name=order.worker_name, worker_surname=order.worker_surname, \
                        department=order.department, date_start=form.date_start.data, date_end=form.date_end.data, \
                            login=order.login, login_status=order.login_status, email=order.email, email_status=order.email_status, \
                                privilege=order.privilege,supervisor=current_user.name + " " + current_user.surname,supervisor_id = current_user.id,user_id=order.user_id)
                db.session.add(order1)
                db.session.commit()
                
                order1  = Order.query.filter_by(user_id=user_id, status_cancel='-').order_by(Order.id.desc()).first()
                order_items = Order_item.query.filter_by(id_order=order.id).all()

                for order_item in order_items:
                    if order_item.value == 'Yes' and order_item.status=='Done' and request.form.get("order_item1_"+str(order_item.id))!="on":
                        value1 = 'Yes'
                        status = 'Done'
                    elif (order_item.value == 'Yes' or order_item.value == '') and order_item.status=='In progress' and request.form.get("order_item1_"+str(order_item.id))!="on":
                        value1 ='Yes'
                        status = 'In progress'
                    elif order_item.value == 'to remove'  and order_item.status=='In progress' and request.form.get("order_item1_"+str(order_item.id))!="on":
                        value1 ='Yes'
                        status = 'In progress'
                    else:
                        if request.form.get("order_item1_"+str(order_item.id))=="on":
                            value1 = 'to remove'
                            status='In progress'
                        else:
                            value1=request.form.get("order_item_"+str(order_item.id))
                            status='In progress'
                    order_itemms= Order_item(id_order=order1.id, id_item=order_item.id, name = order_item.name, value = value1, status=status)
                    db.session.add(order_itemms)
                    db.session.commit()
                for difference in differences:
                    value1=request.form.get(difference)
                    flash(value1)
                    order_itemms= Order_item(id_order=order1.id, id_item=order_item.id, name = difference, value = value1, status=status)
                    db.session.add(order_itemms)
                    db.session.commit()
                flash('Order edit Access Employee has been send','success')
                return redirect(url_for('my_users_orders'))
            except:
                flash('Order edit Access Employee cant be send','danger')
                return redirect(url_for('my_users_orders'))

        return render_template('edit_access_employee1.html',differences=differences,items=items, form=form, order=order, order_items=order_items)


        


if __name__ == '__main__':
    app.run(debug=True)
