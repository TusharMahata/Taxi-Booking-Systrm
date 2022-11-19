
from flask import Flask, redirect, render_template, request, url_for, flash
import random
import flask
import flask_login
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateTimeField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt 
from sqlalchemy import update


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SECRET_KEY'] = 'TUSHARkumarmahata01010'
SQLALCHEMY_TRACK_MODIFICATIONS = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    userrole = db.Column(db.Integer)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    traveler = db.Column(db.String)
    traveldatetime = db.Column(db.String(200))
    travellocation = db.Column(db.String(200))
    drivername = db.Column(db.String(20))




class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder':'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder':'Password'})
    submit = SubmitField('Register')

class BookingForm(FlaskForm):
    traveldatetime = StringField(validators=[InputRequired(), Length(min=4, max=200)], render_kw={'placeholder':'Travel date and time'})
    travellocation = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder':'Travel Locations'})
    submit = SubmitField('Book')


    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username = username.data).first()

        if existing_user_username:
            raise ValidationError(
                'This username already exists. Please choose different one :-) '
            )

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder':'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={'placeholder':'Password'})
    submit = SubmitField('Login')


datas = []


@app.route('/home', methods=['GET', 'POST'])
#@app.route('/')
@login_required
def home():

    if request.method == 'POST':
        title = request.form['title']
        todo = Todo(title=title)
        db.session.add(todo)
        db.session.commit()
        return redirect('/home')

    datas = Todo.query.all()
    return render_template('index.html', data = datas)



@app.route('/normaluser', methods=['GET', 'POST'])
#@app.route('/')
@login_required
def normaluser():
    form = BookingForm()
    booking = Booking.query.filter_by(traveler = str(flask_login.current_user)).all()
    #booking = booking.drivername
    #driverinfo = User.query.filter_by(id = booking.drivername).all()


    if form.validate_on_submit():
       
        booking_request = Booking(traveler = str(flask_login.current_user) ,traveldatetime=form.traveldatetime.data, travellocation = form.travellocation.data)
        #print(form.username.data)
        db.session.add(booking_request)
        db.session.commit()
        # requ = 1
        
        return redirect(url_for('normaluser'))
    return render_template('normaluser.html', form = form, booking = booking)

@app.route('/admindashboard', methods=['GET', 'POST'])
#@app.route('/')
@login_required
def admindashboard():
    datas = Booking.query.all()
    return render_template('admindashboard.html', data = datas)

@app.route('/driverlist/<int:bookingid>', methods=['GET', 'POST'])

#@app.route('/')
@login_required
def driverlist(bookingid):
    datas = db.session.query(User).filter_by(userrole=2).all()
    return render_template('driverlist.html', data = datas, bookingid = bookingid)


@app.route('/allocate/<int:driverid>/<int:bookingid>')
def allocate(driverid, bookingid):
    driver = db.session.query(User).filter_by(id = driverid).first()
    #travel = db.session.query(Booking).filter_by(id = bookingid).first()
    travel = driver.username
    Booking.query.filter_by(id = bookingid).update({Booking.drivername : travel})
    #db.session.update(travel)
    #update(Booking).where(drivername.c.name == 'patrick').values(fullname='Patrick the Star')
    db.session.commit()


    return redirect('/admindashboard')



@app.route('/driverdashboard', methods=['GET', 'POST'])
#@app.route('/')
@login_required
def driverdashboard():
    #driver = db.session.query(User).filter_by(id = str(flask_login.current_user)).first()
    # driverid = driver.id
    #username = driver.username
    #print(flask_login.current_user.username)
    #booking = Booking.query.filter_by(drivername = username).all()
    booking = db.session.query(Booking).filter_by(drivername = flask_login.current_user.username).all()


    return render_template('driverdashboard.html', booking=booking)

@app.route('/remove/<int:todoid>')
def removeTodo(todoid):
    todo = db.session.query(Todo).filter_by(id=todoid).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect('/home')

@app.route('/cancel/<int:taxiid>')
def cancle(taxiid):
    travel = db.session.query(Booking).filter_by(id=taxiid).first()
    db.session.delete(travel)
    db.session.commit()
    return redirect('/normaluser')

@app.route('/removerent/<int:taxiid>')
def remove(taxiid):
    travel = db.session.query(Booking).filter_by(id=taxiid).first()
    db.session.delete(travel)
    db.session.commit()
    return redirect('/admindashboard')

@app.route('/update/<int:todoid>')
def updateTodo(todoid):
        todo = db.session.query(Todo).filter_by(id=todoid).first()
        return render_template('update.html', todo=todo)

@app.route('/tushar', methods=["POST"])
def update():
    title = request.form['title']
    id = request.form['id']
    todo = db.session.query(Todo).filter_by(id=id).first()
    todo.title = title
    db.session.commit()
    return redirect('/home')


@app.route('/login', methods=['GET', 'POST'])
def login():
    msg = ''
    form  = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
       

        # print(user)
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):

                login_user(user) 

                if user.userrole == 3:
                    return redirect(url_for('normaluser'))

                elif user.userrole == 2:
                    return redirect(url_for('driverdashboard'))

                else:   
                    return redirect(url_for('admindashboard'))
            else:
                msg = 'Invalid username or password'
        
        else:
            msg = 'Invalid username or password'
                

    return render_template('login.html', form = form, msg = msg)    

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/landing', methods=['GET','POST'])
@app.route('/')
def landing():
    
    return render_template('landing.html')


@app.route('/register', methods=['GET', 'POST'])

def register():
    userrole = 1
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hashed_password, userrole = userrole)
        #print(form.username.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form = form)


@app.route('/registeruser', methods=['GET', 'POST'])
# @app.route('/')

def registeruser():
    userrole = 3
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hashed_password, userrole = userrole)
        #print(form.username.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('registeruser.html', form = form)


@app.route('/registerdriver', methods=['GET', 'POST']) 
def registerdriver():
    userrole = 2
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password = hashed_password, userrole = userrole)
        #print(form.username.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('registerdriver.html', form = form)
 
 

if __name__ == "__main__":
    app.run(debug=True)