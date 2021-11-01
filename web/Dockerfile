FROM python:3
WORKDIR /usr/src/app
COPY . .
RUN pip install --no-cache-dir -r requierments.txt
RUN pip install en_core_web_sm-3.1.0.tar.gz
CMD [ "python", "app.py" ]