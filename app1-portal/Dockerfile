# base image su dung python 3.12 slim nhe va tiet kiem dung luong
FROM python:3.12-slim

# dat thu muc lam viec ben trong container
WORKDIR /app

# cau hinh bien moi truong python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# copy requirements va cai dat thu vien truoc de toi uu docker layer cache
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# copy toan bo ma nguon va file cau hinh vao container
COPY . .

# khai bao cong dich vu
EXPOSE 3001

# lenh khoi chay ung dung qua uvicorn tai cong 3001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3001"]

