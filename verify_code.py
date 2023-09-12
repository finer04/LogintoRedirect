from flask import Flask
from flask import render_template
from PIL import Image, ImageDraw, ImageFont, ImageFilter


import random
import base64



# 验证码图片
def validate_picture():
    total = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345789'
    # 图片大小130 x 50
    width = 130
    heighth = 50
    # 先生成一个新图片对象
    im = Image.new('RGB', (width, heighth), 'white')
    # 设置字体
    font = ImageFont.truetype("NotoSerif-Bold.ttf", 30)
    # 创建draw对象
    draw = ImageDraw.Draw(im)
    str = ''
    # 输出每一个文字
    for item in range(4):
        text = random.choice(total)
        str += text
        draw.text((-3 + random.randint(3, 7) + 25 * item, -3 + random.randint(2, 7)), text=text, fill='black',
                  font=font)

    # 划几根干扰线
    for num in range(1):
        x1 = random.randint(0, width / 2)
        y1 = random.randint(0, heighth / 2)
        x2 = random.randint(0, width)
        y2 = random.randint(heighth / 2, heighth)
        draw.line(((x1, y1), (x2, y2)), fill='black', width=1)

    # 加上滤镜
    im = im.filter(ImageFilter.FIND_EDGES)
    return im, str







# app = Flask(__name__)
#
#
# @app.route('/')
# def test():
#     data = run_code()  # 生成新验证码
#     return render_template('test.html', img_stream=data)  # 会在下面贴出我的html源码
#
#
# if __name__ == '__main__':
#     app.run(host='0.0.0.0',port="9921", debug=True)