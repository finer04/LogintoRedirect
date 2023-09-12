# 功能
import collections
import pyotp


class OTP:
    def __init__(self, sec=None):
        if sec is None:
            pass
        else:
            self.sec = sec

    def generate(self):
        sec = pyotp.random_base32()
        return sec

    def verify(self, code):
        totp = pyotp.TOTP(self.sec)
        return totp.verify(code)

    def create_uri(self):
        uri = pyotp.totp.TOTP(self.sec).provisioning_uri('login_dengbao')
        return uri

# 角色名转换
def charCN(name):
    cnname = ''
    if name == 'security':
        cnname = '安全员'
    elif name == "main-admin":
        cnname = '总管理员'
    elif name == 'user':
        cnname = '普通用户'
    elif name == 'audit':
        cnname = "审计管理员"
    return cnname


# 检查表格是否为空，用GPT生成的
def check_dict_fields(dictionary):
    for key, value in dictionary.items():
        if not value:
            return False
    return True

# 字符串的1和0转换成T和F
def strtobool(str):
    if str == '1':
        return True
    elif str == '0':
        return  False

# 字符串的1和0转换成T和F
def booltostr(bool):
    if bool is True:
        return '开启'
    elif bool is False:
        return '关闭'



# 排列字典
def co(dic):
    temp_dic = collections.OrderedDict(sorted(dic.items()))
    return temp_dic


# 检查两个字典哪些字段不同
def check_dict_diff(origin, new):
    differences = []
    print(co(new))

    for field, value in co(new).items():
        if co(origin).get(field) != value:
            differences.append(field)

    differences.remove('id')
    return differences
