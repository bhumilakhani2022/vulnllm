FROM ubuntu:18.04

# Install system packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    git \
    vim

# Install Node.js
RUN curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs

# Copy application
COPY . /app
WORKDIR /app

# Install Python dependencies
RUN pip3 install -r requirements.txt

EXPOSE 8000
CMD ["python3", "app.py"]
