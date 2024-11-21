FROM python:3.9-slim
LABEL authors="Alfredo"

# Imposta la directory di lavoro
WORKDIR /app

# Copia il file dei requisiti, se esiste
COPY requirements.txt /app/

# Installa le dipendenze
RUN pip install --no-cache-dir -r requirements.txt

# Copia il resto del codice dell'applicazione nella directory di lavoro
COPY . /app

# Esponi la porta su cui Flask si avvia (default: 5000)
EXPOSE 5000

# Comando di default per eseguire il server
CMD ["python", "main.py", "--host", "0.0.0.0", "--port", "5000"]
