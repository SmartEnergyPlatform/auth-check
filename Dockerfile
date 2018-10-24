FROM python:2

COPY requirements.txt /
RUN pip install --no-cache-dir -r requirements.txt

COPY jwt.py /jwt.py

WORKDIR /

EXPOSE 8080

CMD python -u ./jwt.py

