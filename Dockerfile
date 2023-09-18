FROM python:slim
WORKDIR /app
ADD . /app
RUN pip install --trusted-host  pypi.tuna.tsinghua.edu.cn -r requirements.txt
EXPOSE 5000
ENV MODE="main"
CMD ["sh","-c","python $MODE.py "]