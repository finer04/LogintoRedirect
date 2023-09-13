import time

from flask import Flask, request, render_template, g, jsonify, session,make_response,redirect,url_for
import verify_code as v
import functools
from io import BytesIO
import base64
import os, sys, pyotp, json
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import utils
import logging


# 全局
app = Flask(__name__)
app.config['SECRET_KEY'] = '3c2d9d261a464e4e8814c5a39aa72f1c'
app.config['PERMANENT_SESSION_LIFETIME'] = 300
now = datetime.now()

# 修饰器，登录才可以访问，且必须在允许IP范围内
def login_required(func):
    @functools.wraps(func) # 修饰内层函数，防止当前装饰器去修改被装饰函数的属性
    def inner(*args, **kwargs):
        settings = Settings.query.filter_by(id=1).first()
        limit_ip = settings.white_IP_list
        limit_iplist = limit_ip.split(',')
        # 从session获取用户信息，如果有，则用户已登录，否则没有登录
        user_login = session.get('login')
        if not user_login:
            return redirect('/return')
        else:
            # 已经登录的话 g变量保存用户信息，相当于flask程序的全局变量
            g.user_login = user_login
            if session.get('IP') in limit_iplist or limit_ip == '':
                return func(*args, **kwargs)
            else:
                return 'Your IP is not within the authorized range.'
    return inner

# 修饰器，禁止普通用户访问
def foridden_normal_user(func):
    @functools.wraps(func) # 修饰内层函数，防止当前装饰器去修改被装饰函数的属性
    def inner(*args, **kwargs):
        user_character = session.get('character')
        if user_character == 'user':
            return "you aren't admin"
        else:
            return func(*args, **kwargs)
    return inner

# 初始化数据库
WIN = sys.platform.startswith('win')
if WIN:  # 如果是 Windows 系统，使用三个斜线
    prefix = 'sqlite:///'
else:  # 否则使用四个斜线
    prefix = 'sqlite:////'

app.config['SQLALCHEMY_DATABASE_URI'] = prefix + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # 关闭对模型修改的监控
# 在扩展类实例化前加载配置
db = SQLAlchemy(app)
ip = 0


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)  # 用户名，唯一
    password = db.Column(db.String(20))  # 密码
    OTP_id = db.Column(db.String(30))  # OTP 安全令
    otp_enable = db.Column(db.Boolean, default=True)  # OTP 是否开启
    failure_count = db.Column(db.Integer, default=0)  # 登录失败次数
    failure_last_time = db.Column(db.DateTime, default=now)  # 最后登录失败时间
    password_final_time = db.Column(db.DateTime, nullable=True)  # 密码到期时间
    user_enable = db.Column(db.Boolean, default=True)  # 用户是否启用
    character = db.Column(db.String(20)) # 三权分立之角色分配


class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30))  # 系统标题
    white_IP_list = db.Column(db.Text)  # 白名单IP列表
    session_long = db.Column(db.String(3))  # session 保活时间
    set_login_failure_time = db.Column(db.String(3))  # 登录失败次数限制
    set_login_lock_time = db.Column(db.String(3))  # 登录失败次数锁定时间
    dest_url = db.Column(db.String(100))  # 最终登录系统的地址

##################################################
##
##  展示类
##
##################################################


# 首页，登录界面
@app.route('/')
def index():
    #读取系统信息

    settings = Settings.query.filter_by(id=1).first()
    title = settings.title
    return render_template('index.html', title=title)


# 登录成功跳转正式平台
@app.route('/dest')
@login_required
def main_page():
    # 读取系统信息
    settings = Settings.query.filter_by(id=1).first()
    title = settings.title
    url = settings.dest_url
    return render_template('dest.html', title=title,username = session.get('username'),character=session.get('character'),CNcharacter=utils.charCN(session.get('character')))

# 登录成功跳转正式平台
@app.route('/settings')
@login_required
@foridden_normal_user
def setting_page():
    # 读取系统信息
    settings = Settings.query.filter_by(id=1).first()
    data = {'title': settings.title,
        'url': settings.dest_url,
        'session_long' : settings.session_long,
        'login_f' : settings.set_login_failure_time,
        'login_l' : settings.set_login_lock_time,
        'white_ip' : settings.white_IP_list,
        'character' : session.get('character'),
        'CNcharacter' : utils.charCN(session.get('character')),
        'username':  session.get('username')
    }
    return render_template('settings.html', data=data)

# 真实url跳转
@app.route('/dest/url')
@login_required
def url_redirect():
    settings = Settings.query.filter_by(id=1).first()
    url = settings.dest_url
    return redirect(url)

# 过期session跳转
@app.route('/return')
def return_home():
    # 读取系统信息
    return render_template('return.html')

# 展示所有用户信息
@app.route('/user/show')
@login_required
@foridden_normal_user
def show_user():
    user = User.query # 提前做筛选
    coloum = User.__table__.columns.keys() # 输出表内所有字段
    coloum.remove('password')
    result = []
    for id in range(1,user.count()+1): #遍历每一条列 ID
        user_info = user.filter_by(id=id).first() #输出第 x 条的
        tmp = {}
        tmp['id'] = id
        tmp['result'] = {}
        for c in coloum: #根据字段逐个追加
            tmp['result'][c] = getattr(user_info,c)
        tmp['result']['character'] = utils.charCN(tmp['result']['character'])
        tmp['result']['otp_enable'] = utils.booltostr(tmp['result']['otp_enable'])
        tmp['result']['user_enable'] = utils.booltostr(tmp['result']['user_enable'])
        result.append(tmp) # 列入列表
    return result


##################################################
##
##  交互类
##
##################################################

# 安装界面（初始化平台）
@app.route('/setup', methods=["POST"])
def setup():
    if request.method == 'POST':
        if Settings.query.count() == 0:
            result = request.form
            # 判断所有字段是否为空
            if utils.check_dict_fields(result):
                r = result
                user_record = User(username=r.get('username'), password=r.get('password'), OTP_id=r.get('OTP_id'),character='main-admin')
                setting_record = Settings(title=r.get('title'), white_IP_list=r.get('white_IP_list'),
                                          session_long=r.get('session_long'),
                                          set_login_failure_time=r.get('set_login_failure_time'),
                                          set_login_lock_time=r.get('set_login_lock_time'), dest_url=r.get('dest_url'))
                db.session.add(setting_record)
                db.session.add(user_record)
                db.session.commit()
                return "success"
            else:
                return "form-key have null"
        else:
            return "have installed"


# 全局设置，只对settings表变更
@app.route('/modify/settings', methods=["PUT"])
@login_required
@foridden_normal_user
def modify_settings():
    if request.method == 'PUT':
        # 需要对比settings原来的表单和提交的表单哪些字段有差异，需要列出来
        new_setting_dict = request.form.to_dict()  # 新提交的表单
        settings_record = Settings.query.filter_by(id=1).first()  # 数据库原来的字段
        if settings_record:
            # 将settings表的id=1的key,value转换成字典
            tmp_dict = settings_record.__dict__
            # tmp_dict.pop('_sa_instance_state', None)
            settings_dict = tmp_dict
            print(settings_dict)
            print(new_setting_dict)
            # 对比，获取不同的字段
            diff = utils.check_dict_diff(settings_dict, new_setting_dict)
            print(diff)
            # 如果变更的值，修改数据库对应的字段
            if len(diff) > 0:
                for field in diff:
                    # settings_record.field = new_setting_dict[field]
                    setattr(settings_record, field, new_setting_dict[field])  # 不可以向上面直接写.field，要用setattr替换对象属性
                db.session.commit()
                return 'have changed'
            else:
                return 'no changed'
        else:
            return 'error'


# 用户管理
# 新增用户
@app.route('/user/add', methods=["POST"])
@login_required
@foridden_normal_user
def modify_user():
    if request.method == 'POST':
        form = request.form.to_dict()
        user = User.query.filter_by(username=form['username'])
        if user.count() == 0 :
            if utils.check_password_complexity(form['password']):
                user = User(username=form['username'],password=form['password'],otp_enable=utils.strtobool(form['otp_enable']), OTP_id=form['OTP-id'],failure_last_time=now,character=form['character'])
                db.session.add(user)
                db.session.commit()
                return 'success'
            else:
                return '密码不满足复杂度要求，请修改'
        else:
            return "用户名已存在"

# 用户修改密码
@app.route('/user/modify/password', methods=["PUT"])
@login_required
@foridden_normal_user
def modify_user_password():
    if request.method == 'PUT':
        form = request.form.to_dict()
        user = User.query.filter_by(username=form['username']).first()
        if form['old_password'] == user.password: # 验证旧密码是否跟原来的密码一样
            if form['new_password'] != user.password: # 验证新密码是否跟旧密码是否不一致，一致的话不行
                user.password = form['new_password']
                db.session.commit()
                return 'success'
            else:
                return '新密码不能跟旧密码相同'
        else:
            return '旧密码错误'


# 用户禁用
@app.route('/user/modify/stat', methods=["PUT"])
@login_required
@foridden_normal_user
def modify_user_stat():
    if request.method == 'PUT':
        form = request.form.to_dict()
        user = User.query.filter_by(username=form['username']).first()
        if (user.user_enable):
            user.user_enable = False
            result = '账号已锁定'
        else:
            user.user_enable = True
            result = '账号已解锁'
        db.session.commit()
        return result

# 删除用户
@app.route('/user/delete/<string:username>', methods=["DELETE"])
@login_required
@foridden_normal_user
def delete_user(username):
    if request.method == 'DELETE':
        user = User.query.filter_by(username=username).first()
        if user.id != 1:
            db.session.delete(user)
            db.session.commit()
            return 'success'
        else:
            return '不能删除初始用户'


# 开启/关闭安全令
@app.route('/user/OTP/change', methods=["PUT"])
@login_required
@foridden_normal_user
def change_otp():
    if request.method == 'PUT':
        form = request.form.to_dict()
        user = User.query.filter_by(username=form['username']).first()
        if user.otp_enable:
            user.OTP_id = ''
            user.otp_enable = False
            result = '动态口令已关闭'
        else:
            user.otp_enable = True
            user.OTP_id = utils.OTP().generate()
            result = '动态口令已开启'
        db.session.commit()
        return result

# 安全令
# 生成
@app.route('/otp/create', methods=["GET"])
def otp_code():
    # 如果是生成新的安全令，则
    if request.method == 'GET':
        date = {}
        new_code = utils.OTP().generate()
        date['new_code'] = new_code
        date['new_uri'] = utils.OTP(new_code).create_uri()
        return json.dumps(date)

# 验证
# otp-code 为 安全令原本额ID，now-code是当前验证器的号码
@app.route('/otp/verify', methods=["POST"])
def otp_verify(now_code=None):
    if request.method == 'POST':
        form = request.form
        username = form.get('username')
        user = User.query.filter_by(username=username).first()
        if now_code is None:
            result = utils.OTP(user.OTP_id).verify(form.get('now-code'))
        else:
            result = utils.OTP(user.OTP_id).verify(now_code)
        if result:
            return 'True'
        else:
            return 'False'


# 生成验证码实例的函数
@app.route("/code")
def run_code():
    # 生成验证码，image为验证码图片，code为验证码文本

    image, code = v.validate_picture()

    # 将验证码图片以二进制形式写入在内存中，防止将图片都放在文件夹中，占用大量磁盘
    buf = BytesIO()
    image.save(buf, 'jpeg')
    buf_str = buf.getvalue()

    data = str(base64.b64encode(buf_str))[1:].strip("'")  # 将验证码转换为base64格式
    session['code'] = code  # 将验证码文本存入session，做用户登录认证时可用
    print(str(session))
    response = make_response(buf_str)
    response.headers['Content-Type'] = 'image/jpeg'
    return response
    #return render_template('code.html', img_stream=data)


# 验证环节，需要两个表单，账号（account），密码（password）,验证码（code）
@app.route('/login', methods=["POST", "GET"])
def login():
    # 初始化数据库查询
    setting = Settings.query.filter_by(id=1).first()
    ip = request.remote_addr

    # 内方法，登录成功后的操作
    def success(username,character):
        session['login'] = True  # 记录session已经登录
        session['character'] = character  # 记录用户当前角色
        session['IP'] = ip
        session['username'] = username
        app.logger.info(f'{username} 已登录系统')

    if request.method == 'POST':
        result = request.form.to_dict()
        print(result)
        #提前寻找对应用户的信息
        userinfo = User.query.filter_by(username=result['username']).first()

        # 认证环节
        if userinfo != None:  # 判断用户是否存在
            print(f'{userinfo.username} user exist')
            # 判断现在的时间和上次登录失败是否超过系统的登录锁定时间
            if userinfo.user_enable:
                if userinfo.failure_last_time is not None:
                    last_failure_time = userinfo.failure_last_time
                    duration = now - last_failure_time
                    duration = duration.total_seconds() // 60 # 转换为分钟
                    # 如果登录次数少于系统锁定次数且小于锁定期分钟数的话
                    if userinfo.failure_count <= int(setting.set_login_failure_time) or duration > float(setting.set_login_lock_time):
                        if userinfo.password == result['password']:  # 判断密码是否相同
                            print(f'{userinfo.username} password is right')
                            true_code = session.get("code")
                            if true_code == result['code']:  # 判断验证码是否正确
                                print(f'Verification code is right')
                                if userinfo.otp_enable:  # 是否有安全令
                                    if otp_verify(result['OTP-id']) == 'True':  # 验证安全令有无问题
                                        userinfo.failure_count = 0
                                        db.session.commit()
                                        success(userinfo.username,userinfo.character)
                                        return '登录成功，正在跳转...'
                                    else:
                                        if len(result['OTP-id']) != 0:
                                            return '动态口令错误'
                                        else:
                                            return '该账号已开启二步认证，请填写动态口令'
                                else: #没开启OTP的话，直接通过
                                    userinfo.failure_count = 0
                                    db.session.commit()
                                    success(userinfo.username,userinfo.character)
                                    return '登录成功，正在跳转...'
                            else:  # 验证码错误
                                return "验证码错误"
                        else:  # 密码不正确
                            print(f'{userinfo.username} password not right')
                            # 密码不正确的话，记录登录失败次数和最后登录失败时间
                            userinfo.failure_count += 1
                            userinfo.failure_last_time = now
                            db.session.commit()
                            return '用户名或密码错误'
                    else:
                        return '登录多次失败，已进入锁定期'
            else:
                return '用户被禁用'
        else:  # 用户名错误
            return '用户名或密码错误'

# 登出
@app.route('/logout', methods=["GET"])
def user_logout():
    session.clear()
    return 'logout'


with app.app_context():
    # 设置默认保活时间
    session_long = float(Settings.query.filter_by(id=1).first().session_long) * 60
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=int(session_long))
    print(f"保活时长为 {app.config['PERMANENT_SESSION_LIFETIME']}")
    # 获取终端 IP

if __name__ == "__main__":
    app.debug = True
    handler = logging.FileHandler('log//flask.log', encoding='UTF-8')
    handler.setLevel(logging.DEBUG)  # 设置日志记录最低级别为DEBUG，低于DEBUG级别的日志记录会被忽略，不设置setLevel()则默认为NOTSET级别。
    logging_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(filename)s - %(funcName)s - %(lineno)s - %(message)s')
    handler.setFormatter(logging_format)
    app.logger.addHandler(handler)
    app.run()
